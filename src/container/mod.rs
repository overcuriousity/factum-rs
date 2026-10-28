//! Evidence containers: AFF4-L v1.0 files that preserve files with their metadata and hashes, signed with GPG
//! (and optionally X.509). This module reads and writes the container file; `crate::containers` ties it to the
//! case log.

pub mod mounts;
pub mod source;
pub mod stream;
pub mod turtle;
pub mod verify;
pub mod volume;
pub mod x509;
pub mod zip64;

/// `aff4:` — the AFF4 Standard v1.0 lexicon
pub const AFF4_NS: &str = "http://aff4.org/Schema#";
/// `aff4l:` — terms introduced by AFF4-L v1.0 (the namespace as its section 4.1 gives it)
pub const AFF4L_NS: &str = "https://aff4.org/Schema/2022/#";
/// `factum:` — factum's own facts, which other readers ignore
pub const FACTUM_NS: &str = "https://github.com/overcuriousity/factum-rs/schema/2026#";
pub const XSD_NS: &str = "http://www.w3.org/2001/XMLSchema#";
pub const RDF_NS: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";

/// The ZIP member that holds an ARN (AFF4 Standard v1.0, 5.1 and 5.2): below the volume's ARN, the rest of the
/// ARN, relative to the root; any other ARN under its scheme and GUID URL-encoded, such as
/// `aff4%3A%2F%2F<guid>/00000000` for `aff4://<guid>/00000000`.
pub fn member_name(arn: &str, volume: &str) -> String {
    if let Some(relative) = arn
        .strip_prefix(volume)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|_| !volume.is_empty())
    {
        return relative.to_string();
    }
    match arn.strip_prefix("aff4://") {
        Some(rest) => format!("aff4%3A%2F%2F{rest}"),
        None => arn.to_string(),
    }
}

/// Content up to this size is one ZIP member (ZipSegment); larger content is an ImageStream (AFF4-L v1.0, 6.1).
pub const ZIP_SEGMENT_LIMIT: u64 = 1 << 30;

#[cfg(test)]
mod tests {
    use super::member_name;

    #[test]
    fn member_names_follow_the_standard_section_5() {
        let volume = "aff4://9db79393-53fa-4147-b823-5c3e1d37544d";
        // 5.5: relative to the volume
        assert_eq!(
            member_name(&format!("{volume}/Foobar/foo.txt"), volume),
            "Foobar/foo.txt"
        );
        // 5.5: another GUID, its prefix escaped in upper case
        assert_eq!(
            member_name("aff4://05e11366-036a-4997-8f10-cfbff91256f4/00000000", volume),
            "aff4%3A%2F%2F05e11366-036a-4997-8f10-cfbff91256f4/00000000"
        );
        assert_eq!(
            member_name("aff4://05e11366-036a-4997-8f10-cfbff91256f4", volume),
            "aff4%3A%2F%2F05e11366-036a-4997-8f10-cfbff91256f4"
        );
        // a GUID that merely starts like the volume's is not below it
        assert_eq!(
            member_name(&format!("{volume}0/x"), volume),
            format!("aff4%3A%2F%2F{}0/x", &volume[7..])
        );
        assert_eq!(member_name("aff4://x/y", ""), "aff4%3A%2F%2Fx/y");
    }
}
