//! Indicators of compromise extracted from note text. The helpers do not commit on their own; the calling
//! operation owns the transaction.

use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};

use crate::error::Result;

/// The IOC types in extraction order, with their patterns.
pub static IOC_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    let octet = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])";
    vec![
        (
            "ip",
            Regex::new(&format!(r"\b(?:{octet}\.){{3}}{octet}\b")).unwrap(),
        ),
        (
            "domain",
            Regex::new(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b").unwrap(),
        ),
        (
            "url",
            Regex::new(r"\bhttps?://[^\s/$.?#].[^\s]*\b").unwrap(),
        ),
        (
            "email",
            Regex::new(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b").unwrap(),
        ),
        // longest alternative first, and the word boundaries must apply to every alternative
        (
            "hash",
            Regex::new(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b").unwrap(),
        ),
    ]
});

/// "domains" ending in one of these are almost always file names (evil.exe, notes.txt), not network indicators
pub static DOMAIN_EXCLUDED_SUFFIXES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "exe", "dll", "sys", "bat", "cmd", "ps1", "psm1", "vbs", "js", "jse", "hta", "msi", "scr",
        "lnk", "jar", "py", "pyc", "sh", "bin", "elf", "so", "dylib", "app", "dmg", "pkg", "deb",
        "rpm", "apk", "txt", "log", "csv", "json", "xml", "yml", "yaml", "ini", "cfg", "conf",
        "md", "html", "htm", "php", "asp", "aspx", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
        "ppt", "pptx", "pdf", "rtf", "odt", "zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz",
        "cab", "iso", "img", "vhd", "vhdx", "vmdk", "e01", "dd", "raw", "mem", "dmp", "pcap",
        "pcapng", "evtx", "reg", "db", "sqlite", "dat", "tmp", "bak", "png", "jpg", "jpeg", "gif",
        "bmp", "ico", "svg", "mp3", "mp4", "mov", "avi", "wav",
    ]
    .into_iter()
    .collect()
});

// an entry is the newest version of its line when no other entry corrects it
const NEWEST_VERSION: &str = "NOT EXISTS (SELECT 1 FROM entries s WHERE s.corrects_id = n.id)";

pub fn extract_iocs(text: &str) -> Vec<(String, String)> {
    let mut iocs: Vec<(String, String)> = Vec::new();
    for (ioc_type, pattern) in IOC_PATTERNS.iter() {
        for found in pattern.find_iter(text) {
            let value = found.as_str();
            if *ioc_type == "domain" {
                let suffix = value.rsplit('.').next().unwrap_or("").to_lowercase();
                if DOMAIN_EXCLUDED_SUFFIXES.contains(suffix.as_str()) {
                    continue; // a file name like evil.exe, not a domain
                }
            }
            let item = (ioc_type.to_string(), value.to_string());
            if !iocs.contains(&item) {
                iocs.push(item);
            }
        }
    }
    iocs
}

pub fn parse_ioc_from_note(conn: &Connection, entry_id: i64, text: &str) -> Result<Vec<i64>> {
    let mut new_ids = Vec::new();
    for (ioc_type, value) in extract_iocs(text) {
        let existing: Option<i64> = conn
            .query_row(
                "SELECT id FROM ioc WHERE ioc_type = ? AND ioc_value = ?",
                params![ioc_type, value],
                |r| r.get(0),
            )
            .optional()?;
        let ioc_id = match existing {
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
    log::debug!(
        "Parsed and added {} new IOCs from entry ID {entry_id}",
        new_ids.len()
    );
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
    let rows = statement.query_map([id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
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

pub fn get_iocs_for_evidence(
    conn: &Connection,
    evidence_id: i64,
) -> Result<BTreeMap<String, Vec<String>>> {
    grouped(conn, "evidence_id", evidence_id)
}

pub fn remove_orphaned_iocs(conn: &Connection) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM ioc WHERE id NOT IN (SELECT ioc_id FROM entry_ioc_map)",
        [],
    )?)
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
        assert!(of("domain", "ran evil.exe and notes.TXT").is_empty());
    }

    #[test]
    fn longest_hash_wins() {
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(of("hash", sha256), vec![sha256]);
    }
}
