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
/// The flags a local header has to share with its central entry, because they change how the member is read:
/// encrypted (0), sizes in a data descriptor (3) and UTF-8 name (11). factum writes 0 and 3 clear and 11 set in both;
/// the others (compression options) say nothing a reader acts on.
const FLAGS_COMPARED: u16 = 1 | (1 << 3) | FLAG_UTF8;
const EOCD_LEN: u64 = 22;
const LOCATOR_LEN: u64 = 20;
const EOCD64_LEN: u64 = 56;
const BUFFER: usize = 1 << 20;

/// One member as the central directory lists it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CdEntry {
    pub name: Vec<u8>,
    /// general purpose bit flags
    pub flags: u16,
    /// 0 stored, 8 deflated
    pub method: u16,
    /// MS-DOS time and date the member was written
    pub time: u16,
    pub date: u16,
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

    /// The volume ARN the ZIP comment gives (AFF4 Standard v1.0, 5.4).
    pub fn volume(&self) -> String {
        String::from_utf8_lossy(&self.comment).trim().to_string()
    }

    /// The member that holds an ARN (see `member_name`).
    pub fn get_arn(&self, arn: &str) -> Option<&CdEntry> {
        self.get(&super::member_name(arn, &self.volume()))
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

/// What `read_archive` makes of a read that finds no state: the bytes are not one. Anything else (a failing disk)
/// says nothing about the file.
fn not_a_state(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof)
}

#[cfg(test)]
thread_local! {
    /// A test seam: the n-th read from now fails once, as a failing disk would (0: none).
    pub(crate) static FAIL_READ: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn read_at(file: &mut File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    #[cfg(test)]
    if FAIL_READ.with(|n| n.replace(n.get().saturating_sub(1))) == 1 {
        return Err(io::Error::from_raw_os_error(5));
    }
    let mut buffer = vec![0; len];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// What the end records of a central directory say.
struct EndRecords {
    comment: Vec<u8>,
    count: u64,
    cd_size: u64,
    cd_offset: u64,
}

/// The records that end exactly at `end`, as far as they agree with where they are in the file.
fn read_end_records(file: &mut File, end: u64) -> io::Result<EndRecords> {
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
            if record_offset
                .checked_add(EOCD64_LEN)
                .is_none_or(|e| e > eocd_offset - LOCATOR_LEN)
            {
                return Err(invalid("bad ZIP64 locator"));
            }
            let record = read_at(file, record_offset, EOCD64_LEN as usize)?;
            if u32_at(&record, 0) != EOCD64_SIG {
                return Err(invalid("bad ZIP64 end-of-central-directory record"));
            }
            // right before the locator: a ZIP nested in a member points at offsets of its own, maybe at another record
            let record_end = u64_at(&record, 4)
                .checked_add(record_offset)
                .and_then(|e| e.checked_add(12));
            if record_end != Some(eocd_offset - LOCATOR_LEN) {
                return Err(invalid("bad ZIP64 locator"));
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
    Ok(EndRecords {
        comment,
        count,
        cd_size,
        cd_offset,
    })
}

/// Reads the central directory whose end-of-central-directory record ends exactly at `end`.
pub fn read_archive(file: &mut File, end: u64) -> io::Result<Archive> {
    let EndRecords {
        comment,
        count,
        cd_size,
        cd_offset,
    } = read_end_records(file, end)?;
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
            flags: u16_at(&directory, at + 8),
            method: u16_at(&directory, at + 10),
            time: u16_at(&directory, at + 12),
            date: u16_at(&directory, at + 14),
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
    // an entry behind the count is one factum would not see, and other ZIP readers would
    if at != directory.len() {
        return Err(invalid("the central directory holds more than its entry count"));
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

/// Whether a state ends at `end`. A read error is an error, not a "no".
fn is_state(file: &mut File, end: u64) -> io::Result<bool> {
    match read_archive(file, end) {
        Ok(_) => Ok(true),
        Err(e) if not_a_state(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Offers where each end-of-central-directory record in `from..len` ends, newest first, to `visit`, until it answers.
fn search_back<T>(
    file: &mut File,
    from: u64,
    len: u64,
    mut visit: impl FnMut(&mut File, u64) -> io::Result<Option<T>>,
) -> io::Result<Option<T>> {
    // backwards in blocks that overlap by 3 bytes, so a signature across a block boundary is found
    let mut block_end = len;
    while block_end >= from + 4 {
        let start = block_end.saturating_sub(BUFFER as u64).max(from);
        let block = read_at(file, start, (block_end - start) as usize)?;
        for at in (0..block.len().saturating_sub(3)).rev() {
            if u32_at(&block, at) != EOCD_SIG {
                continue;
            }
            let offset = start + at as u64;
            if offset + EOCD_LEN > len {
                continue;
            }
            let candidate = offset + EOCD_LEN + u16_at(&read_at(file, offset + 20, 2)?, 0) as u64;
            if candidate <= len
                && let Some(found) = visit(file, candidate)?
            {
                return Ok(Some(found));
            }
        }
        if start == from {
            break;
        }
        block_end = start + 3;
    }
    Ok(None)
}

/// The end of the newest complete state: the file's length if it ends with one, else `hint`, else the nearest
/// end-of-central-directory record before the end whose central directory reads (an interrupted append).
pub fn find_last_end(file: &mut File, hint: Option<u64>) -> io::Result<Option<u64>> {
    let len = file.seek(SeekFrom::End(0))?;
    if is_state(file, len)? {
        return Ok(Some(len));
    }
    if let Some(hint) = hint.filter(|h| *h <= len)
        && is_state(file, hint)?
    {
        return Ok(Some(hint));
    }
    search_back(file, 0, len, |file, end| Ok(is_state(file, end)?.then_some(end)))
}

/// The end of the newest complete state, to continue from: the file's length if it ends with one, else the newest
/// state found by walking the members written after `known` (where the case log's state ends); without a usable
/// `known`, the walk starts from the state the backward search finds (`find_last_end`). The walk reads local headers
/// only, so finished members of any size are passed quickly; what it cannot pass is read to the end of the file.
///
/// What lies after the returned end is what an interrupted addition leaves. Bytes that could be more than that are
/// an InvalidData error, and a read error is an error as well: neither says that anything may be cut off. The same
/// goes for an end before `known`: the case log saw a state there, whatever the bytes look like now.
pub fn find_newest_end(file: &mut File, known: Option<u64>) -> io::Result<Option<u64>> {
    let len = file.seek(SeekFrom::End(0))?;
    if is_state(file, len)? {
        return Ok(Some(len));
    }
    let start = match known.filter(|k| *k <= len) {
        Some(known) if is_state(file, known)? => known,
        _ => match find_last_end(file, None)? {
            Some(end) => end,
            None => return Ok(None),
        },
    };
    let end = walk_states(file, start, len)?;
    if let Some(known) = known.filter(|k| end < *k) {
        return Err(invalid(format!(
            "a state ended at offset {known}, the newest one left ends at {end}"
        )));
    }
    Ok(Some(end))
}

/// One step of the walk.
enum Step {
    /// a finished member: the next header is here
    Member(u64),
    /// a complete state ends here
    State(u64),
    /// what a crash leaves: the bytes after this point belong to something never finished
    Interrupted,
    /// bytes the writer never leaves where a header belongs
    Unknown,
}

/// Walks the members after the state ending at `start`, member by member (each local header gives its size), and
/// returns the end of the last complete state it passes. Where the walk cannot go on the rest is searched for what
/// it could hide (`search_tail`). Nothing to continue from there is fine after something interrupted, and an error
/// after bytes that no crash of the writer leaves.
fn walk_states(file: &mut File, start: u64, len: u64) -> io::Result<u64> {
    let mut newest = start;
    let mut pos = start;
    while pos < len {
        let step = if pos + 4 > len {
            if header_or_end_at(file, pos, len)? {
                Step::Interrupted
            } else {
                Step::Unknown
            }
        } else {
            match u32_at(&read_at(file, pos, 4)?, 0) {
                LOCAL_SIG => member_step(file, pos, len)?,
                CENTRAL_SIG => state_end(file, pos, len)?.map_or(Step::Interrupted, Step::State),
                _ => Step::Unknown,
            }
        };
        let unknown = match step {
            Step::Member(next) => {
                pos = next;
                continue;
            }
            Step::State(end) => {
                newest = end;
                pos = end;
                continue;
            }
            Step::Interrupted => false,
            Step::Unknown => true,
        };
        match search_tail(file, pos, len)? {
            Some(end) => {
                newest = end;
                pos = end;
            }
            None if unknown => return Err(invalid(format!("the bytes at offset {pos} are no ZIP header"))),
            None => break,
        }
    }
    Ok(newest)
}

/// The member whose local header is at `pos`. Interrupted when it does not end in the file, and when it has no
/// compressed size yet: factum writes the CRC, the size and the compressed size after the data, in that order, and
/// what follows the header is then content, not a next header. Only a stored member without content has those same
/// zeros when finished: it counts as finished when a header or the end of the file follows. Metadata can be stored
/// empty; a bevy, the one stored member that holds evidence, never is, and evidence may start like a header.
fn member_step(file: &mut File, pos: u64, len: u64) -> io::Result<Step> {
    if pos + 30 > len {
        return Ok(Step::Interrupted);
    }
    let header = read_at(file, pos, 30)?;
    let (name_len, extra_len) = (u16_at(&header, 26) as u64, u16_at(&header, 28) as u64);
    let data = pos + 30 + name_len + extra_len;
    let mut compressed = u32_at(&header, 18) as u64;
    if compressed == 0xFFFF_FFFF {
        if data > len {
            return Ok(Step::Interrupted);
        }
        let extra = read_at(file, pos + 30 + name_len, extra_len as usize)?;
        let mut entry = CdEntry {
            compressed_size: 0xFFFF_FFFF,
            size: 0xFFFF_FFFF,
            ..CdEntry::default()
        };
        apply_zip64_extra(&mut entry, &extra);
        if entry.compressed_size == 0xFFFF_FFFF {
            return Ok(Step::Unknown);
        }
        if entry.compressed_size == 0 {
            let empty = u16_at(&header, 8) == 0 && entry.size == 0 && u32_at(&header, 14) == 0;
            let name = read_at(file, pos + 30, name_len as usize)?;
            if !empty || is_bevy_name(&name) || !header_or_end_at(file, data, len)? {
                return Ok(Step::Interrupted);
            }
        }
        compressed = entry.compressed_size;
    }
    Ok(match data.checked_add(compressed) {
        Some(next) if next <= len => Step::Member(next),
        _ => Step::Interrupted,
    })
}

/// Whether a member is named as the bevies of an ImageStream are: `<stream>/%08d`.
fn is_bevy_name(name: &[u8]) -> bool {
    let number = name
        .iter()
        .rposition(|byte| *byte == b'/')
        .map(|slash| &name[slash + 1..]);
    number.is_some_and(|number| number.len() >= 8 && number.iter().all(u8::is_ascii_digit))
}

/// Whether a header starts at `pos`, whole or cut short by the end of the file, or the file ends there.
fn header_or_end_at(file: &mut File, pos: u64, len: u64) -> io::Result<bool> {
    signature_at(file, pos, len, &[LOCAL_SIG, CENTRAL_SIG])
}

/// Whether one of `signatures` starts at `pos`, whole or cut short by the end of the file.
fn signature_at(file: &mut File, pos: u64, len: u64, signatures: &[u32]) -> io::Result<bool> {
    let start = read_at(file, pos, (len - pos).min(4) as usize)?;
    Ok(signatures.iter().any(|sig| sig.to_le_bytes().starts_with(&start)))
}

/// Where the state whose central directory starts at `pos` ends. None for a directory that runs into the end of the
/// file (interrupted while it was written); a complete one that cannot be read is an error.
fn state_end(file: &mut File, pos: u64, len: u64) -> io::Result<Option<u64>> {
    let unreadable = || invalid(format!("the central directory at offset {pos} cannot be read"));
    let mut at = pos;
    while at + 46 <= len {
        let entry = read_at(file, at, 46)?;
        if u32_at(&entry, 0) != CENTRAL_SIG {
            break;
        }
        at += 46 + u16_at(&entry, 28) as u64 + u16_at(&entry, 30) as u64 + u16_at(&entry, 32) as u64;
    }
    if at >= len {
        return Ok(None);
    }
    if !signature_at(file, at, len, &[CENTRAL_SIG, EOCD64_SIG, EOCD_SIG])? {
        return Err(unreadable());
    }
    if at + 4 > len {
        return Ok(None);
    }
    match u32_at(&read_at(file, at, 4)?, 0) {
        CENTRAL_SIG => return Ok(None),
        EOCD64_SIG => at += EOCD64_LEN + LOCATOR_LEN,
        _ => {}
    }
    if at >= len {
        return Ok(None);
    }
    if !signature_at(file, at, len, &[EOCD_SIG])? {
        return Err(unreadable());
    }
    if at + EOCD_LEN > len {
        return Ok(None);
    }
    let record = read_at(file, at, EOCD_LEN as usize)?;
    // only the comment missing: that its length is damaged cannot be ruled out
    let end = at + EOCD_LEN + u16_at(&record, 20) as u64;
    if end <= len && is_state(file, end)? {
        Ok(Some(end))
    } else {
        Err(unreadable())
    }
}

/// Searches the bytes the walk could not pass. The end of the newest state among them, if any; an error when end
/// records there fit their place in the file but their directory cannot be read: damage to a state, not the end of
/// a file nested in the evidence, whose offsets count from its own start. Without either, the bytes hold no state.
fn search_tail(file: &mut File, from: u64, len: u64) -> io::Result<Option<u64>> {
    search_back(file, from, len, |file, end| {
        if is_state(file, end)? {
            return Ok(Some(end));
        }
        match read_end_records(file, end) {
            Ok(_) => Err(invalid(format!(
                "the state ending at offset {end} is complete but cannot be read"
            ))),
            Err(e) if not_a_state(&e) => Ok(None),
            Err(e) => Err(e),
        }
    })
}

/// The uncompressed content of a member. Its local header has to agree with the central directory: ZIP readers go
/// by one or the other.
pub fn member_reader<'f>(file: &'f mut File, entry: &CdEntry) -> io::Result<Box<dyn Read + 'f>> {
    let header = read_at(file, entry.header_offset, 30)?;
    if u32_at(&header, 0) != LOCAL_SIG {
        return Err(invalid(format!("no local header for {}", entry.name_lossy())));
    }
    let name = read_at(file, entry.header_offset + 30, u16_at(&header, 26) as usize)?;
    if name != entry.name
        || u16_at(&header, 8) != entry.method
        || (u16_at(&header, 6) ^ entry.flags) & FLAGS_COMPARED != 0
    {
        return Err(invalid(format!(
            "the local header of {} differs from the central directory",
            entry.name_lossy()
        )));
    }
    let data = entry.header_offset + 30 + u16_at(&header, 26) as u64 + u16_at(&header, 28) as u64;
    file.seek(SeekFrom::Start(data))?;
    let raw = Read::take(file, entry.compressed_size);
    let checked = |inner: Box<dyn Read + 'f>| -> Box<dyn Read + 'f> {
        Box::new(CrcChecked {
            inner,
            crc: crc32fast::Hasher::new(),
            expected: entry.crc32,
            name: entry.name_lossy(),
        })
    };
    match entry.method {
        0 => Ok(checked(Box::new(raw))),
        // no more than the size the directory gives, whatever the data inflates to
        8 => Ok(checked(Box::new(
            flate2::read::DeflateDecoder::new(raw).take(entry.size),
        ))),
        other => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("compression method {other} of {}", entry.name_lossy()),
        )),
    }
}

/// The error in place of the end of a member that does not have the directory's CRC-32.
#[derive(Debug)]
struct CrcMismatch(String);

impl std::fmt::Display for CrcMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} does not match the CRC-32 of the central directory", self.0)
    }
}

impl std::error::Error for CrcMismatch {}

pub fn crc_error(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, CrcMismatch(name.to_string()))
}

/// The member a CRC-32 error names. All its content was read by then: a check can go by the content, and report the
/// CRC as what it is, one more field of the directory.
pub fn crc_mismatch(error: &io::Error) -> Option<&str> {
    let mismatch = error.get_ref()?.downcast_ref::<CrcMismatch>()?;
    Some(&mismatch.0)
}

/// Passes a member's content through; once it has been read to its end, fails unless it has the directory's CRC-32.
struct CrcChecked<'f> {
    inner: Box<dyn Read + 'f>,
    crc: crc32fast::Hasher,
    expected: u32,
    name: String,
}

impl Read for CrcChecked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.crc.update(&buf[..read]);
        if read == 0 && !buf.is_empty() && self.crc.clone().finalize() != self.expected {
            return Err(crc_error(&self.name));
        }
        Ok(read)
    }
}

/// The most of one member read into memory (metadata, signatures, a bevy of an ImageStream): a crafted container
/// cannot make factum hold more, whatever its directory claims or its data inflates to.
pub const MAX_IN_MEMORY: u64 = 1 << 30;

/// A member's content in memory; refused when it is larger than MAX_IN_MEMORY.
pub fn member_bytes(file: &mut File, entry: &CdEntry) -> io::Result<Vec<u8>> {
    match member_bytes_and_crc(file, entry)? {
        (data, true) => Ok(data),
        (_, false) => Err(crc_error(&entry.name_lossy())),
    }
}

/// A member's content in memory, and whether it has the directory's CRC-32: for what reports that itself.
pub fn member_bytes_and_crc(file: &mut File, entry: &CdEntry) -> io::Result<(Vec<u8>, bool)> {
    member_bytes_up_to(file, entry, MAX_IN_MEMORY)
}

fn member_bytes_up_to(file: &mut File, entry: &CdEntry, limit: u64) -> io::Result<(Vec<u8>, bool)> {
    let mut data = Vec::with_capacity(entry.size.min(limit).min(1 << 24) as usize);
    let read = member_reader(file, entry)?.take(limit + 1).read_to_end(&mut data);
    let crc_matches = match read {
        Ok(_) => true,
        Err(e) if crc_mismatch(&e).is_some() => false,
        Err(e) => return Err(e),
    };
    if data.len() as u64 > limit {
        return Err(invalid(format!("{} is larger than {limit} bytes", entry.name_lossy())));
    }
    Ok((data, crc_matches))
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
    /// read buffer of `add_member`, kept for the next member
    buffer: Vec<u8>,
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
            buffer: Vec::new(),
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
        let mut buffer = std::mem::take(&mut self.buffer);
        buffer.resize(BUFFER, 0);
        let mut counting = Counting {
            inner: &mut self.out,
            count: 0,
        };
        let mut feed = |sink: &mut dyn Write| -> io::Result<()> {
            loop {
                let read = data.read(&mut buffer)?;
                if read == 0 {
                    return Ok(());
                }
                let chunk = &buffer[..read];
                observe(chunk);
                crc.update(chunk);
                size += read as u64;
                sink.write_all(chunk)?;
            }
        };
        let fed = if method == 8 {
            // finished here, not when dropped: an error writing its last bytes is an error of the member
            let mut encoder = flate2::write::DeflateEncoder::new(&mut counting, flate2::Compression::fast());
            feed(&mut encoder).and_then(|()| encoder.finish().map(drop))
        } else {
            feed(&mut counting)
        };
        let compressed_size = counting.count;
        self.buffer = buffer;
        fed?;
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
            flags: FLAG_UTF8,
            method,
            time,
            date,
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
        let cd_offset = self.position;
        self.out.seek(SeekFrom::Start(cd_offset))?;
        let mut directory = Vec::new();
        for entry in &entries {
            directory.extend(CENTRAL_SIG.to_le_bytes());
            directory.extend(VERSION.to_le_bytes()); // made by
            directory.extend(VERSION.to_le_bytes()); // needed
            directory.extend(entry.flags.to_le_bytes());
            directory.extend(entry.method.to_le_bytes());
            directory.extend(entry.time.to_le_bytes());
            directory.extend(entry.date.to_le_bytes());
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

    /// Renames a member `from` to `to` (same length) in its local header and in the central directory: a crafted
    /// duplicate name.
    fn rename_member(path: &std::path::Path, from: &str, to: &str) {
        assert_eq!(from.len(), to.len());
        let mut bytes = std::fs::read(path).unwrap();
        while let Some(at) = bytes.windows(from.len()).position(|w| w == from.as_bytes()) {
            bytes[at..at + to.len()].copy_from_slice(to.as_bytes());
        }
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
        rename_member(&dir.path().join("c.aff4l"), "bbbb", "aaaa");
        let mut file = std::fs::File::open(dir.path().join("c.aff4l")).unwrap();
        let archive = read_archive(&mut file, end).unwrap();
        assert_eq!(archive.duplicates(), vec!["aaaa".to_string()]);
        // like Python's zipfile: the last entry of a name is the one read
        assert_eq!(content(&mut file, &archive, "aaaa"), b"second");
    }

    #[test]
    fn an_entry_behind_the_count_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (end1, end2) = two_states(&dir);
        let mut file = reopened(&dir);
        let record = end2 - 8 - EOCD_LEN - LOCATOR_LEN - EOCD64_LEN;
        poke(&mut file, record + 32, &1u64.to_le_bytes());
        let error = read_archive(&mut file, end2).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("more than its entry count"), "{error}");
        // the state is complete: reading on from the one before does not pass it
        assert_eq!(
            find_newest_end(&mut file, Some(end1)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(read_archive(&mut file, end1).unwrap().entries.len(), 1);
    }

    #[test]
    fn a_local_header_has_to_agree_with_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (_, end) = two_states(&dir);
        let good = std::fs::read(dir.path().join("c.aff4l")).unwrap();
        let mut file = reopened(&dir);
        let archive = read_archive(&mut file, end).unwrap();
        let entry = archive.get("b").unwrap();
        let at = entry.header_offset;
        assert_eq!(content(&mut file, &archive, "b"), b"second state");
        let damaged: [(u64, &[u8]); 5] = [
            (at + 30, b"c"),       // another name
            (at + 26, b"\x02"),    // a longer name
            (at + 8, b"\x08"),     // deflated
            (at + 6, b"\x08\x08"), // a data descriptor
            (at + 6 + 1, b"\x00"), // no UTF-8 flag
        ];
        for (offset, bytes) in damaged {
            poke(&mut file, offset, bytes);
            let error = member_bytes(&mut file, entry).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{offset}");
            assert!(error.to_string().contains("differs from the central"), "{error}");
            poke(&mut file, 0, &good);
        }
        // a flag no reader acts on (compression option) is not compared
        poke(&mut file, at + 6, b"\x02\x08");
        assert_eq!(member_bytes(&mut file, entry).unwrap(), b"second state");
    }

    #[test]
    fn a_member_is_checked_against_the_crc_of_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        // without content both have the CRC-32 0 of nothing
        app.add_bytes("empty", 0, b"").unwrap();
        app.add_bytes("nothing", 8, b"").unwrap();
        let stored = app.add_bytes("stored", 0, b"stored content").unwrap();
        let deflated = app.add_bytes("deflated", 8, &pattern(1 << 16)).unwrap();
        let end = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let archive = read_archive(&mut file, end).unwrap();
        assert_eq!(archive.get("empty").unwrap().crc32, 0);
        for entry in &archive.entries {
            member_bytes(&mut file, entry).unwrap();
        }
        // one byte of the stored content changed
        let at = stored.header_offset + 30 + 6 + 20;
        poke(&mut file, at, b"S");
        let error = member_bytes(&mut file, &stored).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("CRC-32"), "{error}");
        // the directory's CRC changed, the content not: a hard error, or the content and the verdict
        let wrong = CdEntry {
            crc32: deflated.crc32 ^ 1,
            ..deflated.clone()
        };
        let error = member_bytes(&mut file, &wrong).unwrap_err();
        assert_eq!(crc_mismatch(&error), Some("deflated"));
        assert!(error.to_string().contains("CRC-32"), "{error}");
        assert_eq!(
            member_bytes_and_crc(&mut file, &wrong).unwrap(),
            (pattern(1 << 16), false)
        );
        assert_eq!(
            member_bytes_and_crc(&mut file, &deflated).unwrap(),
            (pattern(1 << 16), true)
        );
        // content where the directory says there is none
        let wrong = CdEntry {
            crc32: 0,
            size: 4,
            compressed_size: 4,
            ..stored
        };
        assert!(member_bytes(&mut file, &wrong).is_err());
    }

    #[test]
    fn a_member_keeps_the_time_it_was_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("a", 8, b"first").unwrap();
        let end1 = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let mut entries = read_archive(&mut file, end1).unwrap().entries;
        // the local header and the directory say the same
        let header = read_at(&mut file, 0, 30).unwrap();
        assert_eq!(
            (entries[0].time, entries[0].date),
            (u16_at(&header, 10), u16_at(&header, 12))
        );
        // written long ago: no later finish changes that
        (entries[0].time, entries[0].date) = (0x1234, 0x4321);
        let mut app = Appender::new(file, end1, entries).unwrap();
        app.add_bytes("b", 0, b"second").unwrap();
        let end2 = app.finish(&[], b"").unwrap();
        let end3 = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        for end in [end2, end3] {
            let a = read_archive(&mut file, end).unwrap().get("a").unwrap().clone();
            assert_eq!((a.time, a.date), (0x1234, 0x4321));
        }
    }

    #[test]
    fn lookups_stay_fast_with_many_members() {
        let entries: Vec<CdEntry> = (0..50_000)
            .map(|i| CdEntry {
                name: format!("aff4://{i:036}").into_bytes(),
                header_offset: i,
                ..CdEntry::default()
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
        assert_eq!(member_bytes_up_to(&mut file, &entry, 4 << 20).unwrap().0.len(), 4 << 20);
    }

    #[test]
    fn the_newest_state_is_found_by_walking_from_a_known_one() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("a", 8, b"first state").unwrap();
        let end1 = app.finish(&[], b"aff4://x").unwrap();
        // a state written after it (never logged), then an interrupted member whose content looks like headers
        app.add_bytes("b", 0, &pattern(300 << 10)).unwrap();
        let end2 = app.finish(&[], b"aff4://x").unwrap();
        let mut junk = b"PK\x01\x02".to_vec();
        junk.extend(pattern(2 << 20));
        junk[100_000..100_004].copy_from_slice(b"PK\x05\x06");
        app.add_bytes("c", 0, &junk).unwrap();
        drop(app);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("c.aff4l"))
            .unwrap();
        // the sizes of c were written: cut them back to the placeholder of a member never finished
        let len = file.seek(SeekFrom::End(0)).unwrap();
        file.set_len(len - 1000).unwrap();
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end2));
        assert_eq!(find_newest_end(&mut file, Some(end2)).unwrap(), Some(end2));
        assert_eq!(find_newest_end(&mut file, None).unwrap(), Some(end2));
        // a known end that is no end falls back to the search
        assert_eq!(find_newest_end(&mut file, Some(end1 + 1)).unwrap(), Some(end2));
        // interrupted between the two patches: the CRC of c written, its sizes not
        let at = end2 + 30 + 1 + 4;
        file.seek(SeekFrom::Start(at)).unwrap();
        std::io::Write::write_all(&mut file, &[0u8; 16]).unwrap();
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end2));
        // neither written, and stored: the same bytes as a finished empty member before a directory, which fails
        interrupt_member(&mut file, end2, 1);
        assert_eq!(
            find_newest_end(&mut file, Some(end1)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // content that cannot be a next header: the member is interrupted
        poke(&mut file, end2 + 30 + 1 + 20, b"XXXX");
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end2));
    }

    /// Puts the placeholders back of the member at `at`: as if it was never finished.
    fn interrupt_member(file: &mut std::fs::File, at: u64, name_len: u64) {
        file.seek(SeekFrom::Start(at + 14)).unwrap();
        std::io::Write::write_all(file, &[0u8; 4]).unwrap();
        file.seek(SeekFrom::Start(at + 30 + name_len + 4)).unwrap();
        std::io::Write::write_all(file, &[0u8; 16]).unwrap();
    }

    fn reopened(dir: &tempfile::TempDir) -> std::fs::File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("c.aff4l"))
            .unwrap()
    }

    /// Two states and the end of each.
    fn two_states(dir: &tempfile::TempDir) -> (u64, u64) {
        let mut app = Appender::new(new_file(dir), 0, Vec::new()).unwrap();
        app.add_bytes("a", 8, b"first state").unwrap();
        let end1 = app.finish(&[], b"aff4://x").unwrap();
        app.add_bytes("b", 0, b"second state").unwrap();
        (end1, app.finish(&[], b"aff4://x").unwrap())
    }

    /// The offset of the newest central directory: where its ZIP64 record says.
    fn directory_offset(file: &mut std::fs::File, end: u64, comment_len: u64) -> u64 {
        let record = end - comment_len - EOCD_LEN - LOCATOR_LEN - EOCD64_LEN;
        u64_at(&read_at(file, record, EOCD64_LEN as usize).unwrap(), 48)
    }

    fn poke(file: &mut std::fs::File, at: u64, bytes: &[u8]) {
        file.seek(SeekFrom::Start(at)).unwrap();
        std::io::Write::write_all(file, bytes).unwrap();
    }

    /// A file that starts with `first state` and holds, not yet finished, a copy of a whole container as a member.
    fn nested_container(name: &str, method: u16) -> (tempfile::TempDir, u64) {
        // a ZIP file as evidence: its own headers and end records, with offsets that count from its own start
        let dir = tempfile::tempdir().unwrap();
        two_states(&dir);
        let nested = std::fs::read(dir.path().join("c.aff4l")).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("a", 8, b"first state").unwrap();
        let end1 = app.finish(&[], b"aff4://x").unwrap();
        app.add_bytes(name, method, &nested).unwrap();
        (dir, end1)
    }

    #[test]
    fn an_interrupted_member_is_passed_whatever_it_holds() {
        for method in [0, 8] {
            let (dir, end1) = nested_container("z", method);
            let mut file = reopened(&dir);
            // the CRC of the stored one written, so it cannot be a finished empty member
            poke(&mut file, end1 + 30 + 1 + 4, &[0u8; 16]);
            assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1), "{method}");
            assert_eq!(find_newest_end(&mut file, None).unwrap(), Some(end1), "{method}");
            // its size written, its compressed size not (two writes), whatever the CRC
            poke(&mut file, end1 + 30 + 1 + 4, &7u64.to_le_bytes());
            assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1), "{method}");
            poke(&mut file, end1 + 14, &[0u8; 4]);
            assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1), "{method}");
            // neither sizes nor CRC: deflated, it cannot be finished, even when a header seems to follow
            if method == 8 {
                interrupt_member(&mut file, end1, 1);
                let mut entry = [0u8; 46];
                entry[..4].copy_from_slice(b"PK\x01\x02");
                poke(&mut file, end1 + 30 + 1 + 20, &entry);
                assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1));
            }
        }
    }

    #[test]
    fn a_stored_interrupted_member_that_starts_like_a_header_is_refused_not_cut() {
        // the same bytes as a finished empty member and what follows it: the safe reading is that it may be one
        let (dir, end1) = nested_container("z", 0);
        let mut file = reopened(&dir);
        interrupt_member(&mut file, end1, 1);
        assert_eq!(
            find_newest_end(&mut file, Some(end1)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn an_interrupted_bevy_is_passed_though_it_starts_like_a_header() {
        // a bevy is never empty, so these are the placeholders of one in writing
        let name = "aff4%3A%2F%2Fs/00000000";
        let (dir, end1) = nested_container(name, 0);
        let mut file = reopened(&dir);
        interrupt_member(&mut file, end1, name.len() as u64);
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1));
        assert_eq!(find_newest_end(&mut file, None).unwrap(), Some(end1));
    }

    #[test]
    fn only_a_bevy_has_the_name_of_a_bevy() {
        for name in ["aff4%3A%2F%2Fs/00000000", "s/00000012", "s/123456789"] {
            assert!(is_bevy_name(name.as_bytes()), "{name}");
        }
        for name in [
            "00000000",
            "s/00000000.index",
            "s/0000000",
            "s/0000000x",
            "information.turtle.pubkey.asc",
            "factum/history/1/information.turtle.pubkey.asc",
        ] {
            assert!(!is_bevy_name(name.as_bytes()), "{name}");
        }
    }

    #[test]
    fn a_stored_member_without_content_does_not_hide_a_later_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("a", 8, b"first state").unwrap();
        let end1 = app.finish(&[], b"aff4://x").unwrap();
        // what a finished empty stored member looks like: the placeholders
        app.add_bytes("empty", 0, b"").unwrap();
        app.add_bytes("b", 0, b"after it").unwrap();
        let end2 = app.finish(&[], b"aff4://x").unwrap();
        app.add_bytes("c", 0, b"more").unwrap();
        app.add_bytes("d", 0, &pattern(1 << 20)).unwrap();
        let end3 = app.finish(&[], b"aff4://x").unwrap();
        app.add_bytes("e", 0, &pattern(1000)).unwrap();
        drop(app);
        let mut file = reopened(&dir);
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end3));
        assert_eq!(find_newest_end(&mut file, Some(end2)).unwrap(), Some(end3));
    }

    #[test]
    fn a_stored_member_without_content_does_not_excuse_a_damaged_state() {
        for damage in [(0, &b"XXXX"[..]), (20, &b"\xFF\xFF"[..])] {
            let dir = tempfile::tempdir().unwrap();
            let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
            app.add_bytes("a", 8, b"first state").unwrap();
            let end1 = app.finish(&[], b"aff4://x").unwrap();
            app.add_bytes("empty", 0, b"").unwrap();
            app.add_bytes("b", 0, &pattern(1 << 20)).unwrap();
            let end2 = app.finish(&[], b"aff4://x").unwrap();
            let mut file = app.into_file();
            poke(&mut file, end2 - 8 - EOCD_LEN + damage.0, damage.1);
            for known in [Some(end1), None] {
                let error = find_newest_end(&mut file, known).unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{damage:?} {known:?}");
            }
        }
    }

    #[test]
    fn a_crash_at_any_byte_of_an_addition_leaves_the_state_before() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = Appender::new(new_file(&dir), 0, Vec::new()).unwrap();
        app.add_bytes("a", 8, b"first state").unwrap();
        let end1 = app.finish(&[], b"aff4://x").unwrap();
        let mut members = Vec::new();
        for (name, method) in [("t", 8), ("h", 0), ("s", 8)] {
            let start = app.position();
            app.add_bytes(name, method, &pattern(300)).unwrap();
            members.push((start, app.position()));
        }
        let directory = app.position();
        drop(app);
        let good = std::fs::read(dir.path().join("c.aff4l")).unwrap();
        let mut file = reopened(&dir);
        for len in end1..directory {
            poke(&mut file, 0, &good);
            file.set_len(len).unwrap();
            // the member being written has its placeholders still
            if let Some((start, _)) = members
                .iter()
                .find(|(start, end)| (*start + 30 + 1 + 20..*end).contains(&len))
            {
                interrupt_member(&mut file, *start, 1);
            }
            assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1), "{len}");
            assert_eq!(find_newest_end(&mut file, None).unwrap(), Some(end1), "{len}");
        }
    }

    #[test]
    fn a_state_cut_short_anywhere_leaves_the_one_before() {
        let dir = tempfile::tempdir().unwrap();
        let (end1, end2) = two_states(&dir);
        let mut file = reopened(&dir);
        let comment = end2 - 8;
        for len in (comment..end2).rev() {
            file.set_len(len).unwrap();
            // all but the comment: the same as a damaged comment length, and not cut off
            assert!(find_newest_end(&mut file, Some(end1)).is_err(), "{len}");
        }
        for len in (end1..comment).rev() {
            file.set_len(len).unwrap();
            assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1), "{len}");
            assert_eq!(find_newest_end(&mut file, None).unwrap(), Some(end1), "{len}");
        }
    }

    #[test]
    fn a_complete_state_that_cannot_be_read_is_never_passed() {
        let dir = tempfile::tempdir().unwrap();
        let (end1, end2) = two_states(&dir);
        let mut file = reopened(&dir);
        let directory = directory_offset(&mut file, end2, 8);
        let record = end2 - 8 - EOCD_LEN - LOCATOR_LEN - EOCD64_LEN;
        let good = std::fs::read(dir.path().join("c.aff4l")).unwrap();
        let damaged: [(u64, &[u8]); 5] = [
            (directory, b"XX"),                 // its first entry
            (directory + 46 + 1, b"\xFF\xFF"),  // an entry's name, cut from the next
            (record + 32, &9u64.to_le_bytes()), // a count beyond what is there
            (end2 - 8 - EOCD_LEN, b"XX"),       // the classic record
            (end2 - 8 - 2, b"\xFF\xFF"),        // a comment length beyond the file
        ];
        for (at, bytes) in damaged {
            for tail in [0, 1000] {
                poke(&mut file, 0, &good);
                file.set_len(end2 + tail).unwrap();
                poke(&mut file, at, bytes);
                for known in [Some(end1), None] {
                    let error = find_newest_end(&mut file, known).unwrap_err();
                    assert_eq!(
                        error.kind(),
                        io::ErrorKind::InvalidData,
                        "{at} {tail} {known:?} {error}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_state_is_found_at_the_very_start_of_the_bytes_searched() {
        let dir = tempfile::tempdir().unwrap();
        let (_, end) = two_states(&dir);
        let mut file = reopened(&dir);
        // the blocks of the search end 13 bytes after `from`, short of a whole record
        let from = end - 8 - EOCD_LEN - 5;
        file.set_len(from + 10 + BUFFER as u64).unwrap();
        assert_eq!(
            search_tail(&mut file, from, from + 10 + BUFFER as u64).unwrap(),
            Some(end)
        );
    }

    /// What an interrupted addition leaves after the state ending at `end`: a finished member and one never finished.
    fn interrupted_tail(dir: &tempfile::TempDir, end: u64) {
        let mut app = Appender::new(reopened(dir), end, Vec::new()).unwrap();
        app.add_bytes("c", 8, &pattern(5000)).unwrap();
        let at = app.position();
        app.add_bytes("d", 0, &pattern(5000)).unwrap();
        interrupt_member(&mut app.into_file(), at, 1);
    }

    #[test]
    fn a_member_size_past_the_end_does_not_hide_a_state() {
        let dir = tempfile::tempdir().unwrap();
        let (end1, end2) = two_states(&dir);
        interrupted_tail(&dir, end2);
        let mut file = reopened(&dir);
        // the sizes of b, damaged: the walk loses its way, the state after it is still there
        poke(&mut file, end1 + 30 + 1 + 4 + 8, &(1u64 << 40).to_le_bytes());
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end2));
        // bytes that are no header, the same
        poke(&mut file, end1, b"XXXX");
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end2));
    }

    #[test]
    fn bytes_no_crash_leaves_are_never_passed() {
        let dir = tempfile::tempdir().unwrap();
        let (end1, end2) = two_states(&dir);
        let mut file = reopened(&dir);
        let directory = directory_offset(&mut file, end2, 8);
        // the newest directory and its end records, zeroed: finished members and then nothing a writer leaves
        poke(&mut file, directory, &vec![0u8; (end2 - directory) as usize]);
        for known in [Some(end2), Some(end1), None] {
            let error = find_newest_end(&mut file, known).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{known:?}");
        }
        // members and no directory: an addition interrupted before it
        file.set_len(directory).unwrap();
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1));
        // a part of a header's signature the same, a part of anything else not
        poke(&mut file, directory, b"PK");
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1));
        poke(&mut file, directory, b"\0\0");
        assert!(find_newest_end(&mut file, Some(end1)).is_err());
    }

    #[test]
    fn what_follows_a_directory_is_an_end_record_or_a_part_of_one() {
        let dir = tempfile::tempdir().unwrap();
        let (end1, end2) = two_states(&dir);
        let mut file = reopened(&dir);
        let good = std::fs::read(dir.path().join("c.aff4l")).unwrap();
        let record = end2 - 8 - EOCD_LEN - LOCATOR_LEN - EOCD64_LEN;
        let cases: [(&[u8], bool); 6] = [
            (b"PK", true),
            (b"PK\x06", true),
            (b"PK\x06\x06 a part of the record", true),
            (b"PK\x05\x06 part of it", true),
            (b"\0\0\0", false),
            (b"under twenty-two", false),
        ];
        for (bytes, cut) in cases {
            file.set_len(record).unwrap();
            poke(&mut file, record, bytes);
            let found = find_newest_end(&mut file, Some(end1));
            if cut {
                assert_eq!(found.unwrap(), Some(end1), "{bytes:?}");
            } else {
                assert_eq!(found.unwrap_err().kind(), io::ErrorKind::InvalidData, "{bytes:?}");
            }
        }
        // behind the ZIP64 records only the classic record can follow
        let classic = end2 - 8 - EOCD_LEN;
        let cases: [(&[u8], bool); 3] = [(b"PK\x05", true), (b"\0\0\0", false), (b"under twenty-two", false)];
        for (bytes, cut) in cases {
            poke(&mut file, 0, &good);
            file.set_len(classic).unwrap();
            poke(&mut file, classic, bytes);
            let found = find_newest_end(&mut file, Some(end1));
            assert_eq!(found.is_ok(), cut, "{bytes:?} {found:?}");
        }
    }

    #[test]
    fn an_end_before_the_known_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (end1, end2) = two_states(&dir);
        reopened(&dir).set_len(end1).unwrap();
        interrupted_tail(&dir, end1);
        let mut file = reopened(&dir);
        let len = file.seek(SeekFrom::End(0)).unwrap();
        // the log saw a state there: the bytes after the newest one that is left are not simply an interrupted Add
        for known in [end1 + 1, len - 1, len, len + 1, end2 + (1 << 20)] {
            let error = find_newest_end(&mut file, Some(known)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{known}");
        }
        assert_eq!(find_newest_end(&mut file, Some(end1)).unwrap(), Some(end1));
        assert_eq!(find_newest_end(&mut file, None).unwrap(), Some(end1));
        // nothing after that state: nothing to cut, however far the log got
        file.set_len(end1).unwrap();
        assert_eq!(find_newest_end(&mut file, Some(end2)).unwrap(), Some(end1));
    }

    #[test]
    fn a_read_error_is_an_error_not_a_missing_state() {
        let dir = tempfile::tempdir().unwrap();
        let (end1, end2) = two_states(&dir);
        interrupted_tail(&dir, end2);
        let mut file = reopened(&dir);
        for known in [Some(end1), Some(end2), None] {
            // each read in turn fails once
            for n in 1.. {
                FAIL_READ.with(|fail| fail.set(n));
                let found = find_newest_end(&mut file, known);
                if FAIL_READ.with(|fail| fail.replace(0)) != 0 {
                    assert_eq!(found.unwrap(), Some(end2));
                    break;
                }
                assert_eq!(found.unwrap_err().raw_os_error(), Some(5), "{known:?} {n}");
            }
        }
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
