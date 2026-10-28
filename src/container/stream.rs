//! File content in the container, hashed (MD5, SHA-1, SHA-256) in the same pass that stores it: a ZipSegment (one
//! ZIP member) up to the limit, an ImageStream (AFF4 Standard v1.0: zlib chunks in bevies with an index) above it.

use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use sha2::Digest;

use super::AFF4_NS;
use super::zip64::{Appender, Archive, member_bytes};

pub const CHUNK_SIZE: u64 = 32 * 1024;
pub const CHUNKS_PER_SEGMENT: u64 = 2048;
/// `aff4:compressionMethod` of factum's ImageStreams
pub const ZLIB: &str = "https://www.ietf.org/rfc/rfc1950.txt";
const STORED: [&str; 2] = [
    "http://aff4.org/Schema#compression/stored",
    "http://aff4.org/Schema#NullCompressor",
];
const BUFFER: usize = 1 << 20;
/// limits for ImageStreams written by other tools (factum writes 32 KiB and 2048)
const MAX_CHUNK_SIZE: u64 = 64 << 20;
const MAX_CHUNKS_PER_SEGMENT: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

impl Digests {
    /// (datatype local name in the aff4 namespace, value), as `aff4:hash` writes them
    pub fn typed(&self) -> [(&'static str, &str); 3] {
        [("MD5", &self.md5), ("SHA1", &self.sha1), ("SHA256", &self.sha256)]
    }

    pub fn datatype(name: &str) -> String {
        format!("{AFF4_NS}{name}")
    }
}

/// MD5, SHA-1 and SHA-256 at once.
#[derive(Default)]
pub struct Hasher {
    md5: md5::Md5,
    sha1: sha1::Sha1,
    sha256: sha2::Sha256,
}

impl Hasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.md5.update(bytes);
        self.sha1.update(bytes);
        self.sha256.update(bytes);
    }

    pub fn finish(self) -> Digests {
        Digests {
            md5: hex::encode(self.md5.finalize()),
            sha1: hex::encode(self.sha1.finalize()),
            sha256: hex::encode(self.sha256.finalize()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    ZipSegment,
    ImageStream { chunks: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub storage: Storage,
    pub size: u64,
    pub digests: Digests,
}

fn cancelled() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "cancelled")
}

/// Passes reads through, reporting the bytes read so far and failing with `Interrupted` once cancelled.
struct Watched<'a> {
    inner: &'a mut dyn Read,
    total: u64,
    progress: &'a dyn Fn(u64),
    cancel: &'a AtomicBool,
}

impl Read for Watched<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
        let read = self.inner.read(buf)?;
        self.total += read as u64;
        (self.progress)(self.total);
        Ok(read)
    }
}

/// Stores `src` under `arn`: a deflated ZipSegment below `limit` bytes (by `size_hint`), an ImageStream from it on.
pub fn store(
    app: &mut Appender,
    arn: &str,
    src: &mut dyn Read,
    size_hint: u64,
    limit: u64,
    progress: &dyn Fn(u64),
    cancel: &AtomicBool,
) -> io::Result<Stored> {
    if size_hint >= limit {
        return store_image_stream(app, arn, src, CHUNKS_PER_SEGMENT, progress, cancel);
    }
    let mut hasher = Hasher::new();
    let mut watched = Watched {
        inner: src,
        total: 0,
        progress,
        cancel,
    };
    let entry = app.add_member(arn, 8, &mut watched, &mut |bytes| hasher.update(bytes))?;
    Ok(Stored {
        storage: Storage::ZipSegment,
        size: entry.size,
        digests: hasher.finish(),
    })
}

/// Fills `buf` as far as the source allows; returns how much was read (less only at the end).
fn read_full(src: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..])? {
            0 => break,
            read => filled += read,
        }
    }
    Ok(filled)
}

/// An ImageStream: chunks of CHUNK_SIZE, each zlib-compressed unless that does not save at least 16 bytes (then
/// stored raw, padded to CHUNK_SIZE, as pyaff4 does), `chunks_per_segment` to a bevy member `<arn>/%08d` with its
/// index `<arn>/%08d.index` of (u64 offset, u32 length) entries.
pub fn store_image_stream(
    app: &mut Appender,
    arn: &str,
    src: &mut dyn Read,
    chunks_per_segment: u64,
    progress: &dyn Fn(u64),
    cancel: &AtomicBool,
) -> io::Result<Stored> {
    let mut watched = Watched {
        inner: src,
        total: 0,
        progress,
        cancel,
    };
    let mut hasher = Hasher::new();
    let mut chunk = vec![0u8; CHUNK_SIZE as usize];
    let (mut bevy, mut index) = (Vec::new(), Vec::new());
    let (mut size, mut chunks, mut bevy_number, mut in_bevy) = (0u64, 0u64, 0u64, 0u64);
    let flush = |app: &mut Appender, bevy: &mut Vec<u8>, index: &mut Vec<u8>, number: u64| -> io::Result<()> {
        app.add_bytes(&format!("{arn}/{number:08}"), 0, bevy)?;
        app.add_bytes(&format!("{arn}/{number:08}.index"), 0, index)?;
        bevy.clear();
        index.clear();
        Ok(())
    };
    loop {
        let read = read_full(&mut watched, &mut chunk)?;
        if read == 0 {
            break;
        }
        let data = &chunk[..read];
        hasher.update(data);
        size += read as u64;
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data)?;
        let compressed = encoder.finish()?;
        let offset = bevy.len() as u64;
        let length = if (compressed.len() as u64) < CHUNK_SIZE - 16 {
            bevy.extend(&compressed);
            compressed.len()
        } else {
            bevy.extend(data);
            bevy.resize(offset as usize + CHUNK_SIZE as usize, 0);
            CHUNK_SIZE as usize
        };
        index.extend(offset.to_le_bytes());
        index.extend((length as u32).to_le_bytes());
        chunks += 1;
        in_bevy += 1;
        if in_bevy == chunks_per_segment {
            flush(app, &mut bevy, &mut index, bevy_number)?;
            bevy_number += 1;
            in_bevy = 0;
        }
        if read < CHUNK_SIZE as usize {
            break;
        }
    }
    if in_bevy > 0 {
        flush(app, &mut bevy, &mut index, bevy_number)?;
    }
    Ok(Stored {
        storage: Storage::ImageStream { chunks },
        size,
        digests: hasher.finish(),
    })
}

/// Hashes without storing (metadata-only files).
pub fn hash_only(src: &mut dyn Read, progress: &dyn Fn(u64), cancel: &AtomicBool) -> io::Result<(u64, Digests)> {
    let mut watched = Watched {
        inner: src,
        total: 0,
        progress,
        cancel,
    };
    let mut hasher = Hasher::new();
    let mut buffer = vec![0; BUFFER];
    loop {
        let read = watched.read(&mut buffer)?;
        if read == 0 {
            return Ok((watched.total, hasher.finish()));
        }
        hasher.update(&buffer[..read]);
    }
}

/// Reads an ImageStream back, one bevy in memory at a time.
pub fn image_stream_reader<'f>(
    file: &'f mut File,
    archive: &Archive,
    arn: &str,
    size: u64,
    chunk_size: u64,
    chunks_per_segment: u64,
    compression: &str,
) -> io::Result<Box<dyn Read + 'f>> {
    Ok(Box::new(open_image_stream(
        file,
        archive,
        arn,
        size,
        chunk_size,
        chunks_per_segment,
        compression,
    )?))
}

/// An ImageStream that can also seek (for the ranges a Map takes from it).
pub fn open_image_stream<'f>(
    file: &'f mut File,
    archive: &Archive,
    arn: &str,
    size: u64,
    chunk_size: u64,
    chunks_per_segment: u64,
    compression: &str,
) -> io::Result<ImageStreamReader<'f>> {
    let zlib = if compression == ZLIB {
        true
    } else if STORED.contains(&compression) {
        false
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("compression {compression}"),
        ));
    };
    // values from a container's metadata: implausible ones are refused before anything is allocated for them
    if !(1..=MAX_CHUNK_SIZE).contains(&chunk_size) || !(1..=MAX_CHUNKS_PER_SEGMENT).contains(&chunks_per_segment) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("implausible chunk size {chunk_size} or chunks per segment {chunks_per_segment}"),
        ));
    }
    Ok(ImageStreamReader {
        file,
        archive: archive.clone(),
        arn: arn.to_string(),
        size,
        chunk_size,
        chunks_per_segment,
        zlib,
        position: 0,
        bevy: None,
        chunk: Vec::new(),
        chunk_at: 0,
    })
}

/// A loaded bevy: its number, its data and its index of (offset, length).
type Bevy = (u64, Vec<u8>, Vec<(u64, u32)>);

pub struct ImageStreamReader<'f> {
    file: &'f mut File,
    archive: Archive,
    arn: String,
    size: u64,
    chunk_size: u64,
    chunks_per_segment: u64,
    zlib: bool,
    position: u64,
    /// the loaded bevy: its number, data and index
    bevy: Option<Bevy>,
    chunk: Vec<u8>,
    chunk_at: usize,
}

impl ImageStreamReader<'_> {
    fn member(&mut self, name: &str) -> io::Result<Vec<u8>> {
        let entry = self
            .archive
            .get(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("member {name} is missing")))?
            .clone();
        member_bytes(self.file, &entry)
    }

    fn load_chunk(&mut self, number: u64) -> io::Result<()> {
        let bevy_number = number / self.chunks_per_segment;
        if self.bevy.as_ref().is_none_or(|(n, _, _)| *n != bevy_number) {
            let data = self.member(&format!("{}/{bevy_number:08}", self.arn))?;
            let raw_index = self.member(&format!("{}/{bevy_number:08}.index", self.arn))?;
            let index = raw_index
                .as_chunks::<12>()
                .0
                .iter()
                .map(|e| {
                    (
                        u64::from_le_bytes(e[..8].try_into().unwrap()),
                        u32::from_le_bytes(e[8..].try_into().unwrap()),
                    )
                })
                .collect();
            self.bevy = Some((bevy_number, data, index));
        }
        let (_, data, index) = self.bevy.as_ref().unwrap();
        let bad = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("chunk {number} of {} is damaged", self.arn),
            )
        };
        let &(offset, length) = index.get((number % self.chunks_per_segment) as usize).ok_or_else(bad)?;
        let stored = data
            .get(offset as usize..offset as usize + length as usize)
            .ok_or_else(bad)?;
        self.chunk = if self.zlib && u64::from(length) != self.chunk_size {
            // never more than one chunk, whatever the compressed data inflates to
            let mut out = Vec::with_capacity(self.chunk_size as usize);
            flate2::read::ZlibDecoder::new(stored)
                .take(self.chunk_size + 1)
                .read_to_end(&mut out)
                .map_err(|_| bad())?;
            if out.len() as u64 > self.chunk_size {
                return Err(bad());
            }
            out
        } else {
            stored.to_vec()
        };
        // the last chunk may be padded
        let remaining = self.size - number * self.chunk_size;
        self.chunk.truncate(remaining.min(self.chunk_size) as usize);
        self.chunk_at = 0;
        Ok(())
    }
}

impl io::Seek for ImageStreamReader<'_> {
    fn seek(&mut self, to: io::SeekFrom) -> io::Result<u64> {
        let target = match to {
            io::SeekFrom::Start(at) => at as i128,
            io::SeekFrom::End(delta) => self.size as i128 + delta as i128,
            io::SeekFrom::Current(delta) => self.position as i128 + delta as i128,
        };
        if target < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"));
        }
        self.position = target as u64;
        // the chunk is loaded again at the new position
        self.chunk.clear();
        self.chunk_at = 0;
        Ok(self.position)
    }
}

impl Read for ImageStreamReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.size || buf.is_empty() {
            return Ok(0);
        }
        if self.chunk_at >= self.chunk.len() {
            self.load_chunk(self.position / self.chunk_size)?;
            self.chunk_at = (self.position % self.chunk_size) as usize;
            if self.chunk_at >= self.chunk.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("{} ends early", self.arn),
                ));
            }
        }
        let count = buf.len().min(self.chunk.len() - self.chunk_at);
        buf[..count].copy_from_slice(&self.chunk[self.chunk_at..self.chunk_at + count]);
        self.chunk_at += count;
        self.position += count as u64;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::zip64::{Appender, read_archive};
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::sync::atomic::AtomicBool;

    fn appender(dir: &tempfile::TempDir) -> Appender {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.path().join("c.aff4l"))
            .unwrap();
        Appender::new(file, 0, Vec::new()).unwrap()
    }

    fn sample() -> Vec<u8> {
        // half zeros (compress well), half pseudo-random (do not)
        let mut data = vec![0u8; 100 << 10];
        let mut state = 0x2545_f491_4f6c_dd1du64;
        data.extend((0..100 << 10).map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        }));
        data
    }

    #[test]
    fn zip_segment_digests_of_abc() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = appender(&dir);
        let progress = std::cell::Cell::new(0);
        let stored = store(
            &mut app,
            "aff4://a",
            &mut &b"abc"[..],
            3,
            1 << 30,
            &|bytes| progress.set(bytes),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(matches!(stored.storage, Storage::ZipSegment));
        assert_eq!(stored.size, 3);
        assert_eq!(progress.get(), 3);
        assert_eq!(stored.digests.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(stored.digests.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            stored.digests.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let end = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let archive = read_archive(&mut file, end).unwrap();
        assert_eq!(archive.entries.len(), 1);
        assert!(archive.get("aff4://a").is_some());
    }

    #[test]
    fn image_stream_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = appender(&dir);
        let data = sample();
        let stored = store(
            &mut app,
            "aff4://big",
            &mut data.as_slice(),
            data.len() as u64,
            1,
            &|_| {},
            &AtomicBool::new(false),
        )
        .unwrap();
        let chunks = (data.len() as u64).div_ceil(CHUNK_SIZE);
        assert!(matches!(stored.storage, Storage::ImageStream { chunks: c } if c == chunks));
        let (size, digests) = hash_only(&mut data.as_slice(), &|_| {}, &AtomicBool::new(false)).unwrap();
        assert_eq!((stored.size, &stored.digests), (size, &digests));
        let end = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let archive = read_archive(&mut file, end).unwrap();
        let names: Vec<String> = archive.entries.iter().map(|e| e.name_lossy()).collect();
        assert_eq!(names, vec!["aff4://big/00000000", "aff4://big/00000000.index"]);
        assert_eq!(archive.get("aff4://big/00000000.index").unwrap().size, 12 * chunks);
        // the zeros were compressed, the noise was stored raw
        assert!(archive.get("aff4://big/00000000").unwrap().size < data.len() as u64);
        let mut back = Vec::new();
        image_stream_reader(
            &mut file,
            &archive,
            "aff4://big",
            data.len() as u64,
            CHUNK_SIZE,
            CHUNKS_PER_SEGMENT,
            ZLIB,
        )
        .unwrap()
        .read_to_end(&mut back)
        .unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn image_stream_spans_bevies() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = appender(&dir);
        let data = sample();
        // three chunks per bevy, to get several bevies from a small input
        store_image_stream(
            &mut app,
            "aff4://s",
            &mut data.as_slice(),
            3,
            &|_| {},
            &AtomicBool::new(false),
        )
        .unwrap();
        let end = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let archive = read_archive(&mut file, end).unwrap();
        assert!(archive.get("aff4://s/00000002").is_some());
        let mut back = Vec::new();
        image_stream_reader(&mut file, &archive, "aff4://s", data.len() as u64, CHUNK_SIZE, 3, ZLIB)
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn unknown_compression_is_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = appender(&dir);
        let end = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let archive = read_archive(&mut file, end).unwrap();
        let error = image_stream_reader(
            &mut file,
            &archive,
            "aff4://s",
            1,
            CHUNK_SIZE,
            1,
            "http://code.google.com/p/snappy/",
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn cancel_interrupts() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = appender(&dir);
        let cancel = AtomicBool::new(true);
        for limit in [1 << 30, 1] {
            let error = store(&mut app, "aff4://c", &mut &b"abc"[..], 3, limit, &|_| {}, &cancel).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        }
        let error = hash_only(&mut &b"abc"[..], &|_| {}, &cancel).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    }

    #[test]
    #[ignore = "writes 1.1 GiB; run by hand with --ignored"]
    fn large_file_uses_image_stream() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("big");
        let size = (1u64 << 30) + (100 << 20);
        let file = std::fs::File::create(&source).unwrap();
        file.set_len(size).unwrap();
        let mut app = appender(&dir);
        let stored = store(
            &mut app,
            "aff4://l",
            &mut std::fs::File::open(&source).unwrap(),
            size,
            crate::container::ZIP_SEGMENT_LIMIT,
            &|_| {},
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(matches!(stored.storage, Storage::ImageStream { .. }));
        let end = app.finish(&[], b"").unwrap();
        let mut file = app.into_file();
        let archive = read_archive(&mut file, end).unwrap();
        let mut reader = image_stream_reader(
            &mut file,
            &archive,
            "aff4://l",
            size,
            CHUNK_SIZE,
            CHUNKS_PER_SEGMENT,
            ZLIB,
        )
        .unwrap();
        let (read, digests) = hash_only(&mut reader, &|_| {}, &AtomicBool::new(false)).unwrap();
        assert_eq!((read, digests), (size, stored.digests));
    }
}
