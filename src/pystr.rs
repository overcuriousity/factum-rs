//! Python's string semantics where factum's behaviour depends on them, so the port treats text exactly
//! like the original (what counts as whitespace, where lines break).

/// Python's `str.isspace()`: Rust's White_Space plus the ASCII information separators U+001C..U+001F.
pub fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Python's `str.strip()` without arguments.
pub fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// Python's `str.lstrip()` without arguments.
pub fn lstrip(text: &str) -> &str {
    text.trim_start_matches(is_space)
}

fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\u{b}'
            | '\u{c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// Python's `str.splitlines()`: splits on every line boundary, "\r\n" counts once, no trailing empty line.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        if is_line_break(c) {
            lines.push(&text[start..index]);
            let mut end = index + c.len_utf8();
            if c == '\r' && matches!(chars.peek(), Some((_, '\n'))) {
                chars.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// The first `count` characters (not bytes) of text, like Python's `text[:count]`.
pub fn head(text: &str, count: usize) -> &str {
    match text.char_indices().nth(count) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

/// The last `count` characters of text, like Python's `text[-count:]`.
pub fn tail(text: &str, count: usize) -> &str {
    let total = text.chars().count();
    if total <= count {
        return text;
    }
    let (index, _) = text
        .char_indices()
        .nth(total - count)
        .expect("index is in range");
    &text[index..]
}

/// Python's `html.escape(text)` (quote=True).
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Python's `repr()` of a string, used in user-facing messages that quote values.
pub fn repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines_like_python() {
        assert_eq!(splitlines("a\r\nb\rc\n\nd\n"), vec!["a", "b", "c", "", "d"]);
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(splitlines("x\u{2028}y"), vec!["x", "y"]);
    }

    #[test]
    fn strip_like_python() {
        assert_eq!(strip("\u{1f} x \n"), "x");
        assert_eq!(lstrip("  x "), "x ");
    }

    #[test]
    fn head_and_tail_count_characters() {
        assert_eq!(head("Müller", 2), "Mü");
        assert_eq!(tail("ABCDEFGH12345678", 8), "12345678");
        assert_eq!(tail("ab", 8), "ab");
    }

    #[test]
    fn html_escape_like_python() {
        assert_eq!(
            html_escape("<a href=\"x\">'&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&#x27;&amp;&#x27;&lt;/a&gt;"
        );
    }

    #[test]
    fn repr_like_python() {
        assert_eq!(repr("abc"), "'abc'");
        assert_eq!(repr("it's"), "\"it's\"");
        assert_eq!(repr("a\nb"), "'a\\nb'");
    }
}
