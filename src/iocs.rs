//! Indicators of compromise extracted from note text. The helpers do not commit on their own; the calling
//! operation owns the transaction.

use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use rusqlite::{Connection, params};

use crate::error::Result;

/// The IOC types in extraction order, with their patterns.
pub static IOC_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    let octet = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
    // labels may hold any Unicode letter or digit (IDN); the last label is letters only, or punycode
    let tld = r"(?:(?i:xn)--[a-zA-Z0-9-]+|\p{L}{2,})";
    vec![
        ("ip", Regex::new(&format!(r"\b(?:{octet}\.){{3}}{octet}\b")).unwrap()),
        (
            "domain",
            Regex::new(&format!(r"\b(?:[\p{{L}}\p{{N}}-]+\.)+{tld}\b")).unwrap(),
        ),
        // everything up to whitespace or <>"', the trailing punctuation is trimmed in extract_iocs
        ("url", Regex::new(r#"(?i:https?)://[^\s/$.?#<>"'][^\s<>"']*"#).unwrap()),
        (
            "email",
            Regex::new(&format!(r"\b[\p{{L}}\p{{N}}._%+-]+@[\p{{L}}\p{{N}}.-]+\.{tld}\b")).unwrap(),
        ),
        // longest alternative first, and the word boundaries must apply to every alternative
        (
            "hash",
            Regex::new(r"\b(?:[a-fA-F0-9]{128}|[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b").unwrap(),
        ),
    ]
});

/// "domains" ending in one of these are almost always file names (evil.exe, notes.txt), not network indicators.
/// Suffixes that are real TLDs (zip, mov, app, sh, py, md, ...) are deliberately not listed: they are valid
/// domains and an indicator missed is worse than a file name taken for one.
pub static DOMAIN_EXCLUDED_SUFFIXES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "exe", "dll", "sys", "bat", "cmd", "ps1", "psm1", "vbs", "js", "jse", "hta", "msi", "scr", "lnk", "jar", "pyc",
        "bin", "pkg", "elf", "dylib", "dmg", "deb", "rpm", "apk", "txt", "log", "csv", "json", "xml", "yml", "yaml",
        "ini", "cfg", "conf", "html", "htm", "php", "asp", "aspx", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt",
        "pptx", "pdf", "rtf", "odt", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "iso", "img", "vhd", "vhdx", "vmdk",
        "e01", "dd", "raw", "mem", "dmp", "pcap", "pcapng", "evtx", "reg", "db", "sqlite", "dat", "tmp", "bak", "png",
        "jpg", "jpeg", "gif", "bmp", "ico", "svg", "mp3", "mp4", "avi", "wav",
    ]
    .into_iter()
    .collect()
});

// an entry is the newest version of its line when no other entry corrects it
const NEWEST_VERSION: &str = "NOT EXISTS (SELECT 1 FROM entries s WHERE s.corrects_id = n.id)";

/// A URL as found in text loses the punctuation that belongs to the sentence around it.
fn trim_url(url: &str) -> &str {
    let mut url = url;
    loop {
        let Some(last) = url.chars().next_back() else {
            return url;
        };
        let closing = match last {
            ')' => Some('('),
            ']' => Some('['),
            _ => None,
        };
        let unbalanced = closing.is_some_and(|open| url.matches(last).count() > url.matches(open).count());
        if matches!(last, '.' | ',' | ';' | ':' | '!' | '?') || unbalanced {
            url = &url[..url.len() - last.len_utf8()];
        } else {
            return url;
        }
    }
}

/// The stored form of a value: domains, emails and hashes lowercased, URLs with scheme and host lowercased.
fn normalize(ioc_type: &str, value: &str) -> String {
    if ioc_type == "url" {
        let scheme_end = value.find("://").map_or(0, |i| i + 3);
        let authority_end = value[scheme_end..]
            .find(['/', '?', '#'])
            .map_or(value.len(), |i| scheme_end + i);
        let authority = &value[scheme_end..authority_end];
        // user:pass@ keeps its case, only the host is folded
        let host_start = authority.rfind('@').map_or(0, |i| i + 1);
        format!(
            "{}{}{}{}",
            value[..scheme_end].to_lowercase(),
            &authority[..host_start],
            authority[host_start..].to_lowercase(),
            &value[authority_end..]
        )
    } else {
        value.to_lowercase()
    }
}

pub fn extract_iocs(text: &str) -> Vec<(String, String)> {
    let mut iocs: Vec<(String, String)> = Vec::new();
    for (ioc_type, pattern) in IOC_PATTERNS.iter() {
        for found in pattern.find_iter(text) {
            let mut value = found.as_str();
            if *ioc_type == "url" {
                value = trim_url(value);
                if value.ends_with("://") {
                    continue; // nothing after the scheme
                }
            }
            if *ioc_type == "domain" {
                let suffix = value.rsplit('.').next().unwrap_or("").to_lowercase();
                if DOMAIN_EXCLUDED_SUFFIXES.contains(suffix.as_str()) {
                    continue; // a file name like evil.exe, not a domain
                }
            }
            let item = (ioc_type.to_string(), normalize(ioc_type, value));
            if !iocs.contains(&item) {
                iocs.push(item);
            }
        }
    }
    iocs
}

/// The id of a stored IOC equal to `value`, also when an older row was stored with different case.
fn find_existing(conn: &Connection, ioc_type: &str, value: &str) -> Result<Option<i64>> {
    let mut statement = conn.prepare_cached(
        "SELECT id, ioc_value FROM ioc WHERE ioc_type = ? AND lower(ioc_value) = lower(?) ORDER BY id",
    )?;
    let rows = statement.query_map(params![ioc_type, value], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (id, stored) = row?;
        if normalize(ioc_type, &stored) == value {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

pub fn parse_ioc_from_note(conn: &Connection, entry_id: i64, text: &str) -> Result<Vec<i64>> {
    let mut new_ids = Vec::new();
    for (ioc_type, value) in extract_iocs(text) {
        let ioc_id = match find_existing(conn, &ioc_type, &value)? {
            Some(id) => id,
            None => {
                conn.execute(
                    "INSERT INTO ioc (ioc_type, ioc_value) VALUES (?, ?)",
                    params![ioc_type, value],
                )?;
                let id = conn.last_insert_rowid();
                log::debug!("IOC added with ID: {id}");
                new_ids.push(id);
                id
            }
        };
        conn.execute(
            "INSERT OR IGNORE INTO entry_ioc_map (entry_id, ioc_id) VALUES (?, ?)",
            params![entry_id, ioc_id],
        )?;
    }
    log::debug!("Parsed and added {} new IOCs from entry ID {entry_id}", new_ids.len());
    Ok(new_ids)
}

pub fn get_iocs_for_entry(conn: &Connection, entry_id: i64) -> Result<Vec<(String, String)>> {
    let mut statement = conn.prepare_cached(
        "SELECT i.ioc_type, i.ioc_value FROM ioc i JOIN entry_ioc_map nim ON i.id = nim.ioc_id WHERE nim.entry_id = ?",
    )?;
    let rows = statement.query_map([entry_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

fn grouped(conn: &Connection, column: &str, id: i64) -> Result<BTreeMap<String, Vec<String>>> {
    let sql = format!(
        "SELECT DISTINCT i.ioc_type, i.ioc_value FROM ioc i JOIN entry_ioc_map nim ON i.id = nim.ioc_id \
         JOIN entries n ON nim.entry_id = n.id WHERE n.{column} = ? AND {NEWEST_VERSION} ORDER BY i.ioc_type, i.ioc_value"
    );
    let mut statement = conn.prepare(&sql)?;
    let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let rows = statement.query_map([id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
    for row in rows {
        let (ioc_type, value) = row?;
        result.entry(ioc_type).or_default().push(value);
    }
    Ok(result)
}

/// IOCs of the newest versions of a case's entries, grouped by type.
pub fn get_iocs_for_case(conn: &Connection, case_id: i64) -> Result<BTreeMap<String, Vec<String>>> {
    grouped(conn, "case_id", case_id)
}

pub fn get_iocs_for_evidence(conn: &Connection, evidence_id: i64) -> Result<BTreeMap<String, Vec<String>>> {
    grouped(conn, "evidence_id", evidence_id)
}

pub fn remove_orphaned_iocs(conn: &Connection) -> Result<usize> {
    Ok(conn.execute("DELETE FROM ioc WHERE id NOT IN (SELECT ioc_id FROM entry_ioc_map)", [])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn of(kind: &str, text: &str) -> Vec<String> {
        extract_iocs(text)
            .into_iter()
            .filter(|(t, _)| t == kind)
            .map(|(_, v)| v)
            .collect()
    }

    #[test]
    fn extracts_each_type() {
        let text = "beacon to 10.0.0.1 and 256.1.1.1, evil.example.com via https://evil.example.com/x?a=1 \
                    mail bob@corp.example.org hash d41d8cd98f00b204e9800998ecf8427e";
        assert_eq!(of("ip", text), vec!["10.0.0.1"]);
        assert!(of("domain", text).contains(&"evil.example.com".to_string()));
        assert_eq!(of("url", text), vec!["https://evil.example.com/x?a=1"]);
        assert_eq!(of("email", text), vec!["bob@corp.example.org"]);
        assert_eq!(of("hash", text), vec!["d41d8cd98f00b204e9800998ecf8427e"]);
    }

    #[test]
    fn file_names_are_not_domains() {
        assert!(of("domain", "ran evil.exe and notes.TXT, a.bin b.pkg").is_empty());
        assert_eq!(of("domain", "evil.cab"), vec!["evil.cab"]);
    }

    #[test]
    fn longest_hash_wins() {
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(of("hash", sha256), vec![sha256]);
    }

    #[test]
    fn idn_domains_and_emails() {
        let text = "see münchen.de, bob@bücher.example, xn--mnchen-3ya.de and пример.рф";
        assert_eq!(
            of("domain", text),
            vec!["münchen.de", "bücher.example", "xn--mnchen-3ya.de", "пример.рф"]
        );
        assert_eq!(of("email", text), vec!["bob@bücher.example"]);
        assert_eq!(of("domain", "http://example.xn--p1ai/"), vec!["example.xn--p1ai"]);
    }

    #[test]
    fn real_tlds_are_domains() {
        for name in ["evil.zip", "cdn.mov", "x.app", "a.sh", "b.py", "c.so", "d.md"] {
            assert_eq!(of("domain", name), vec![name.to_string()], "{name}");
        }
    }

    #[test]
    fn urls_keep_trailing_slash_and_lose_sentence_punctuation() {
        assert_eq!(of("url", "go to https://evil.com/ now"), vec!["https://evil.com/"]);
        assert_eq!(
            of("url", "(see https://evil.com/a_(b))."),
            vec!["https://evil.com/a_(b)"]
        );
        assert_eq!(of("url", "(see https://evil.com/x), then"), vec!["https://evil.com/x"]);
        assert_eq!(of("url", "[https://evil.com/x]"), vec!["https://evil.com/x"]);
        assert_eq!(of("url", "is it https://evil.com/x?!"), vec!["https://evil.com/x"]);
        assert!(of("url", "see http://! now").is_empty());
        assert!(of("url", "http://: and http://)").is_empty());
        assert_eq!(of("url", "<https://evil.com/x>"), vec!["https://evil.com/x"]);
        assert_eq!(of("url", "\"https://evil.com/x\", ok"), vec!["https://evil.com/x"]);
    }

    #[test]
    fn sha512_is_one_hash() {
        let sha512 = "a".repeat(128);
        assert_eq!(of("hash", &sha512), vec![sha512.clone()]);
    }

    #[test]
    fn case_is_folded_before_dedup() {
        assert_eq!(of("domain", "Evil.COM and evil.com"), vec!["evil.com"]);
        assert_eq!(of("email", "Bob@Corp.COM bob@corp.com"), vec!["bob@corp.com"]);
        assert_eq!(
            of(
                "hash",
                "D41D8CD98F00B204E9800998ECF8427E d41d8cd98f00b204e9800998ecf8427e"
            )
            .len(),
            1
        );
        // the path keeps its case
        assert_eq!(
            of("url", "HTTPS://Evil.COM/Path https://evil.com/Path"),
            vec!["https://evil.com/Path"]
        );
        assert_eq!(of("url", "https://evil.com/A https://evil.com/a").len(), 2);
        assert_eq!(
            of("url", "https://Bob:PaSs@Evil.COM/x"),
            vec!["https://Bob:PaSs@evil.com/x"]
        );
    }

    #[test]
    fn existing_row_with_other_case_is_reused() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE ioc (id INTEGER PRIMARY KEY, ioc_type TEXT, ioc_value TEXT);
             CREATE TABLE entry_ioc_map (entry_id INTEGER, ioc_id INTEGER, UNIQUE(entry_id, ioc_id));
             INSERT INTO ioc (ioc_type, ioc_value) VALUES ('domain', 'Evil.COM'), ('url', 'HTTPS://Evil.COM/Path');",
        )
        .unwrap();
        let new = parse_ioc_from_note(&conn, 1, "Evil.com https://EVIL.com/Path https://evil.com/path").unwrap();
        assert_eq!(new.len(), 1, "only the url with another path is new");
        let rows: i64 = conn.query_row("SELECT COUNT(*) FROM ioc", [], |r| r.get(0)).unwrap();
        assert_eq!(rows, 3);
        let mapped: i64 = conn
            .query_row("SELECT COUNT(*) FROM entry_ioc_map", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mapped, 3);
    }
}
