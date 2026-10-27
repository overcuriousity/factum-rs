//! Evidence containers: AFF4-L v1.0 files that preserve files with their metadata and hashes, signed with GPG
//! (and optionally X.509). This module reads and writes the container file; `crate::containers` ties it to the
//! case log.

pub mod source;
pub mod stream;
pub mod turtle;
pub mod zip64;

/// `aff4:` — the AFF4 Standard v1.0 lexicon
pub const AFF4_NS: &str = "http://aff4.org/Schema#";
/// `aff4l:` — terms introduced by AFF4-L v1.0 (the namespace as its section 4.1 gives it)
pub const AFF4L_NS: &str = "https://aff4.org/Schema/2022/#";
/// `factum:` — factum's own facts, which other readers ignore
pub const FACTUM_NS: &str = "https://github.com/overcuriousity/factum-rs/schema/2026#";
pub const XSD_NS: &str = "http://www.w3.org/2001/XMLSchema#";
pub const RDF_NS: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

/// Content up to this size is one ZIP member (ZipSegment); larger content is an ImageStream (AFF4-L v1.0, 6.1).
pub const ZIP_SEGMENT_LIMIT: u64 = 1 << 30;
