//! The exact serialisations every hash and signature in factum is computed over; verify.py repeats them.
//! They must stay byte-identical to Python's `json.dumps(value, sort_keys=True, separators=(",", ":"),
//! ensure_ascii=False)`, so databases and bundles of the Python and the Rust version verify each other.

use serde_json::Value;

/// Canonical JSON: keys sorted by code point, no whitespace, non-ASCII characters unescaped.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, None, 0);
    out
}

/// `json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)`, used for case.json in bundles.
pub fn pretty_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value, Some(2), 0);
    out
}

fn write_string(out: &mut String, text: &str) {
    // serde_json escapes exactly like Python with ensure_ascii=False: \" \\ \b \f \n \r \t, other controls as \u00xx
    out.push_str(&serde_json::to_string(text).expect("strings always serialise"));
}

fn newline(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(width) = indent {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', width * level));
    }
}

fn write_value(out: &mut String, value: &Value, indent: Option<usize>, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_value(out, item, indent, level + 1);
            }
            newline(out, indent, level);
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            // sorted explicitly: serde_json's map keeps insertion order when a dependency enables preserve_order
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_string(out, key);
                out.push_str(if indent.is_some() { ": " } else { ":" });
                write_value(out, &map[key], indent, level + 1);
            }
            newline(out, indent, level);
            out.push('}');
        }
    }
}

/// ISO 8601 with milliseconds, e.g. 2026-10-05T14:03:22.417Z
pub fn utc_now() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// File-name friendly form of a utc_now() timestamp: 20261005T140322417Z
pub fn compact_utc(timestamp: &str) -> String {
    timestamp.replace(['-', ':', '.'], "")
}

/// Return the signed text of an OpenPGP clearsigned block without checking the signature.
pub fn extract_clearsigned_text(block: &str) -> Option<String> {
    let lines = crate::pystr::splitlines(block);
    let start = lines
        .iter()
        .position(|line| *line == "-----BEGIN PGP SIGNED MESSAGE-----")?;
    let end = start
        + lines[start..]
            .iter()
            .position(|line| *line == "-----BEGIN PGP SIGNATURE-----")?;
    let mut body = &lines[start + 1..end];
    // armor headers ("Hash: SHA512") end with the first empty line
    if let Some(blank) = body.iter().position(|line| line.is_empty()) {
        body = &body[blank + 1..];
    }
    // RFC 4880 §7.1: lines starting with "-" are dash-escaped as "- -"
    let unescaped: Vec<&str> = body
        .iter()
        .map(|line| line.strip_prefix("- ").unwrap_or(line))
        .collect();
    Some(unescaped.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys_and_has_no_whitespace() {
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": [1, null], "c": "x"})),
            r#"{"a":[1,null],"b":1,"c":"x"}"#
        );
    }

    #[test]
    fn canonical_json_keeps_non_ascii_characters() {
        assert_eq!(
            canonical_json(&json!({"t": "Müller ✓"})),
            r#"{"t":"Müller ✓"}"#
        );
    }

    #[test]
    fn canonical_json_escapes_like_python() {
        assert_eq!(
            canonical_json(&json!("a\"\\\n\r\t\u{8}\u{c}\u{1}\u{7f}\u{2028}")),
            "\"a\\\"\\\\\\n\\r\\t\\b\\f\\u0001\u{7f}\u{2028}\""
        );
    }

    #[test]
    fn pretty_json_matches_python_indent() {
        let value = json!({"b": [1, {"x": null}], "a": {}, "c": []});
        assert_eq!(
            pretty_json(&value),
            "{\n  \"a\": {},\n  \"b\": [\n    1,\n    {\n      \"x\": null\n    }\n  ],\n  \"c\": []\n}"
        );
    }

    #[test]
    fn utc_now_format() {
        let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$").unwrap();
        assert!(re.is_match(&utc_now()));
    }

    #[test]
    fn compact_utc_strips_separators() {
        assert_eq!(
            compact_utc("2026-10-05T14:03:22.417Z"),
            "20261005T140322417Z"
        );
    }

    const CLEARSIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n{\"a\":1}\n- -----BEGIN PGP SIGNATURE----- inside the text\n-----BEGIN PGP SIGNATURE-----\n\niHUEARYKAB0WIQ==\n-----END PGP SIGNATURE-----\n";

    #[test]
    fn extract_clearsigned_text_undoes_dash_escaping() {
        assert_eq!(
            extract_clearsigned_text(CLEARSIGNED).unwrap(),
            "{\"a\":1}\n-----BEGIN PGP SIGNATURE----- inside the text"
        );
    }

    #[test]
    fn extract_clearsigned_text_handles_crlf() {
        assert_eq!(
            extract_clearsigned_text(&CLEARSIGNED.replace('\n', "\r\n")).unwrap(),
            "{\"a\":1}\n-----BEGIN PGP SIGNATURE----- inside the text"
        );
    }

    #[test]
    fn extract_clearsigned_text_rejects_other_text() {
        assert_eq!(extract_clearsigned_text("{\"a\":1}"), None);
    }
}
