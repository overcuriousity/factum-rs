//! RDF Turtle: a writer with a fixed layout (one triple per line, so `verify_container.py` can read it without a
//! Turtle library) and a reader for the subset AFF4 containers use.

use std::collections::HashMap;
use std::fmt::Write as _;

use super::{AFF4_NS, AFF4L_NS, RDF_NS, XSD_NS};

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
/// the aff4l namespace as the standard's examples write it
const AFF4L_HTTP_NS: &str = "http://aff4.org/Schema/2022/#";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Iri(String),
    /// `datatype` is a full IRI; None for a plain string
    Literal {
        value: String,
        datatype: Option<String>,
    },
}

impl Term {
    fn text_len(&self) -> u64 {
        match self {
            Term::Iri(iri) => iri.len() as u64,
            Term::Literal { value, datatype } => (value.len() + datatype.as_ref().map_or(0, String::len)) as u64,
        }
    }

    pub fn iri(&self) -> Option<&str> {
        match self {
            Term::Iri(iri) => Some(iri),
            Term::Literal { .. } => None,
        }
    }

    /// The lexical value of a literal.
    pub fn value(&self) -> Option<&str> {
        match self {
            Term::Literal { value, .. } => Some(value),
            Term::Iri(_) => None,
        }
    }

    pub fn datatype(&self) -> Option<&str> {
        match self {
            Term::Literal { datatype, .. } => datatype.as_deref(),
            Term::Iri(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Triple {
    pub subject: String,
    pub predicate: String,
    pub object: Term,
}

/// Triples in the order they were added, with an index by subject (lookups stay fast in graphs of many files).
#[derive(Debug, Clone, Default)]
pub struct Graph {
    triples: Vec<Triple>,
    by_subject: HashMap<String, Vec<usize>>,
}

impl PartialEq for Graph {
    fn eq(&self, other: &Self) -> bool {
        self.triples == other.triples
    }
}

impl Eq for Graph {}

/// The IRI and its synonyms: a term of the aff4 lexicon may be written in the aff4 or the aff4l namespace (AFF4-L
/// v1.0, 4.1), and the aff4l namespace with http or https.
fn synonyms(iri: &str) -> Vec<String> {
    for namespace in [AFF4_NS, AFF4L_NS, AFF4L_HTTP_NS] {
        if let Some(local) = iri.strip_prefix(namespace) {
            return [AFF4_NS, AFF4L_NS, AFF4L_HTTP_NS]
                .iter()
                .map(|ns| format!("{ns}{local}"))
                .collect();
        }
    }
    vec![iri.to_string()]
}

impl Graph {
    pub fn add(&mut self, subject: &str, predicate: &str, object: Term) {
        self.by_subject
            .entry(subject.to_string())
            .or_default()
            .push(self.triples.len());
        self.triples.push(Triple {
            subject: subject.into(),
            predicate: predicate.into(),
            object,
        });
    }

    pub fn extend(&mut self, other: Graph) {
        for triple in other.triples {
            self.add(&triple.subject, &triple.predicate, triple.object);
        }
    }

    pub fn triples(&self) -> &[Triple] {
        &self.triples
    }

    /// Everything said about a subject, as (predicate, object), sorted: equal for two graphs that describe the
    /// subject alike.
    pub fn about(&self, subject: &str) -> Vec<(&str, &Term)> {
        let mut found: Vec<(&str, &Term)> = self
            .by_subject
            .get(subject)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|&index| (self.triples[index].predicate.as_str(), &self.triples[index].object))
            .collect();
        found.sort_by(|a, b| {
            a.0.cmp(b.0)
                .then_with(|| format!("{:?}", a.1).cmp(&format!("{:?}", b.1)))
        });
        found
    }

    /// The objects of `subject`'s `predicate` (or a synonym of it), in order.
    pub fn objects<'g>(&'g self, subject: &str, predicate: &str) -> impl Iterator<Item = &'g Term> {
        let predicates = synonyms(predicate);
        self.by_subject
            .get(subject)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|&index| &self.triples[index])
            .filter(move |t| predicates.contains(&t.predicate))
            .map(|t| &t.object)
    }

    pub fn first_value(&self, subject: &str, predicate: &str) -> Option<&str> {
        self.objects(subject, predicate).find_map(Term::value)
    }

    /// The subjects with `rdf:type` `type_iri` (or a synonym of it), each once, in order.
    pub fn subjects_of_type<'g>(&'g self, type_iri: &str) -> impl Iterator<Item = &'g str> {
        let types = synonyms(type_iri);
        let mut seen = std::collections::HashSet::new();
        self.triples
            .iter()
            .filter(move |t| t.predicate == RDF_TYPE && t.object.iri().is_some_and(|o| types.iter().any(|x| x == o)))
            .map(|t| t.subject.as_str())
            .filter(move |s| seen.insert(*s))
    }

    pub fn has_type(&self, subject: &str, type_iri: &str) -> bool {
        let types = synonyms(type_iri);
        self.objects(subject, RDF_TYPE)
            .any(|o| o.iri().is_some_and(|o| types.iter().any(|x| x == o)))
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // control characters, and what other tools take for a line break, as \uXXXX
            c if (c as u32) < 0x20 || matches!(c, '\u{7f}' | '\u{85}' | '\u{2028}' | '\u{2029}') => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// What the Turtle grammar does not allow between `<` and `>`, written or escaped.
fn not_in_iri(c: char) -> bool {
    c <= ' ' || "<>\"{}|^`\\".contains(c)
}

/// `<iri>`. What an IRI cannot hold is %-encoded, so whatever an IRI holds, it stays one term on one line; an IRI
/// that can be written as it is stays as it is.
fn iri_ref(iri: &str) -> String {
    let mut out = String::with_capacity(iri.len() + 2);
    out.push('<');
    for c in iri.chars() {
        if not_in_iri(c) || c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
            for byte in c.encode_utf8(&mut [0; 4]).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        } else {
            out.push(c);
        }
    }
    out.push('>');
    out
}

/// `prefix:local` when a prefix covers the IRI and the local part is plain, else `<iri>`.
fn compact(iri: &str, prefixes: &[(&str, &str)]) -> String {
    for (prefix, namespace) in prefixes {
        if let Some(local) = iri.strip_prefix(namespace)
            && !local.is_empty()
            && local.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return format!("{prefix}:{local}");
        }
    }
    iri_ref(iri)
}

/// Writes the graph: the prefixes, then each subject (in the order they first appear) with one triple per line.
pub fn write(graph: &Graph, prefixes: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (prefix, namespace) in prefixes {
        let _ = writeln!(out, "@prefix {prefix}: {} .", iri_ref(namespace));
    }
    let mut order: Vec<&str> = Vec::new();
    let mut by_subject: HashMap<&str, Vec<&Triple>> = HashMap::new();
    for triple in &graph.triples {
        let list = by_subject.entry(&triple.subject).or_default();
        if list.is_empty() {
            order.push(&triple.subject);
        }
        list.push(triple);
    }
    for subject in order {
        let triples = &by_subject[subject];
        let _ = write!(out, "\n{}\n", iri_ref(subject));
        for (index, triple) in triples.iter().enumerate() {
            let predicate = if triple.predicate == RDF_TYPE {
                "a".to_string()
            } else {
                compact(&triple.predicate, prefixes)
            };
            let object = match &triple.object {
                Term::Iri(iri) => compact(iri, prefixes),
                Term::Literal { value, datatype } => match datatype {
                    Some(datatype) => format!("\"{}\"^^{}", escape(value), compact(datatype, prefixes)),
                    None => format!("\"{}\"", escape(value)),
                },
            };
            let end = if index + 1 == triples.len() { '.' } else { ';' };
            let _ = writeln!(out, "    {predicate} {object} {end}");
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Iri(String),
    Name(String),
    Str(String),
    LangTag,
    Carets,
    Dot,
    Semicolon,
    Comma,
    Open(char),
    Directive(String),
}

impl Token {
    fn text_len(&self) -> u64 {
        match self {
            Token::Iri(text) | Token::Name(text) | Token::Str(text) | Token::Directive(text) => text.len() as u64,
            _ => 0,
        }
    }
}

/// The character of a `\u` or `\U` escape whose digits start at `at`, and where they end.
fn uchar(text: &str, at: usize, escaped: char) -> Result<(char, usize), String> {
    let len = if escaped == 'u' { 4 } else { 8 };
    let hex = text.get(at..at + len).ok_or("bad \\u escape")?;
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("bad \\u escape".into());
    }
    let code = u32::from_str_radix(hex, 16).map_err(|_| "bad \\u escape")?;
    Ok((char::from_u32(code).ok_or("bad \\u escape")?, at + len))
}

/// What a token holds in memory, its text apart, while the graph is built from it: only while it is.
const TOKEN_COST: u64 = 96;
/// What a parsed line of factum's layout holds in memory, its text apart (a triple, a subject, a prefix), as measured on
/// large containers. `verify_container.py` charges the same.
const LINE_COST: u64 = 200;
pub const TOO_MUCH: &str = "more metadata than fits the memory set aside for it";

/// `at` walks the text by bytes and stays on character boundaries: what delimits a token is ASCII, which is never a
/// part of another character.
///
/// Returns the tokens and what they hold in memory, as they stay held while the graph is built from them.
fn tokenize(text: &str, budget: u64) -> Result<(Vec<Token>, u64), String> {
    let bytes = text.as_bytes();
    let char_at = |at: usize| text[at..].chars().next();
    let mut tokens: Vec<Token> = Vec::new();
    let mut at = 0;
    let delimiter = |c: char| c.is_whitespace() || ";,<>\"'()[]#".contains(c);
    // what the tokens so far hold: each owns its text, and a long one holds it while it grows
    let (mut counted, mut held) = (0, 0);
    while let Some(c) = char_at(at) {
        if c.is_whitespace() {
            at += c.len_utf8();
        } else if c == '#' {
            at = text[at..].find('\n').map_or(text.len(), |n| at + n);
        } else if c == '<' {
            at += 1;
            let mut iri = String::new();
            loop {
                if held + iri.capacity() as u64 > budget {
                    return Err(TOO_MUCH.into());
                }
                let mut ch = char_at(at).ok_or("unterminated IRI")?;
                at += ch.len_utf8();
                if ch == '>' {
                    break;
                }
                if ch == '\\' {
                    let escaped = char_at(at).filter(|e| matches!(e, 'u' | 'U'));
                    let escaped = escaped.ok_or("an IRI allows only \\u and \\U escapes")?;
                    (ch, at) = uchar(text, at + 1, escaped)?;
                }
                if not_in_iri(ch) {
                    return Err(format!("{ch:?} is not allowed in an IRI"));
                }
                iri.push(ch);
            }
            tokens.push(Token::Iri(iri));
        } else if c == '"' || c == '\'' {
            let quote = c as u8;
            let long = bytes.get(at + 1) == Some(&quote) && bytes.get(at + 2) == Some(&quote);
            at += if long { 3 } else { 1 };
            let mut value = String::new();
            loop {
                if held + value.capacity() as u64 > budget {
                    return Err(TOO_MUCH.into());
                }
                let Some(ch) = char_at(at) else {
                    return Err("unterminated string".into());
                };
                if long && ch == c && bytes.get(at + 1) == Some(&quote) && bytes.get(at + 2) == Some(&quote) {
                    at += 3;
                    break;
                }
                if !long && ch == c {
                    at += 1;
                    break;
                }
                if !long && ch == '\n' {
                    return Err("line break in a short string".into());
                }
                if ch == '\\' {
                    let escaped = char_at(at + 1).ok_or("unterminated string")?;
                    at += 1 + escaped.len_utf8();
                    match escaped {
                        't' => value.push('\t'),
                        'b' => value.push('\u{8}'),
                        'n' => value.push('\n'),
                        'r' => value.push('\r'),
                        'f' => value.push('\u{c}'),
                        '"' | '\'' | '\\' => value.push(escaped),
                        'u' | 'U' => {
                            let (decoded, end) = uchar(text, at, escaped)?;
                            value.push(decoded);
                            at = end;
                        }
                        other => return Err(format!("unknown escape \\{other}")),
                    }
                    continue;
                }
                value.push(ch);
                at += ch.len_utf8();
            }
            tokens.push(Token::Str(value));
        } else if c == '@' {
            let start = at + 1;
            at = start;
            while bytes.get(at).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-') {
                at += 1;
            }
            let word = &text[start..at];
            // after a string it is a language tag, otherwise a directive
            if matches!(tokens.last(), Some(Token::Str(_))) {
                tokens.push(Token::LangTag);
            } else {
                tokens.push(Token::Directive(word.to_ascii_lowercase()));
            }
        } else if c == '^' && bytes.get(at + 1) == Some(&b'^') {
            tokens.push(Token::Carets);
            at += 2;
        } else if c == ';' {
            tokens.push(Token::Semicolon);
            at += 1;
        } else if c == ',' {
            tokens.push(Token::Comma);
            at += 1;
        } else if c == '.' && char_at(at + 1).is_none_or(delimiter) {
            tokens.push(Token::Dot);
            at += 1;
        } else if "()[]".contains(c) {
            tokens.push(Token::Open(c));
            at += 1;
        } else {
            let start = at;
            while let Some(ch) = char_at(at).filter(|ch| !delimiter(*ch)) {
                at += ch.len_utf8();
            }
            // a delimiter nothing above takes: left where it is, this would never end
            if at == start {
                return Err(format!("unexpected {c:?}"));
            }
            if held + (at - start) as u64 > budget {
                return Err(TOO_MUCH.into());
            }
            let mut word = text[start..at].to_string();
            // a name never ends with a dot: that one ends the statement
            let mut dots = 0;
            while word.ends_with('.') {
                word.pop();
                dots += 1;
            }
            tokens.push(Token::Name(word));
            tokens.extend(std::iter::repeat_n(Token::Dot, dots.min(1)));
        }
        for token in &tokens[counted..] {
            held += TOKEN_COST + token.text_len();
        }
        counted = tokens.len();
        if held > budget {
            return Err(TOO_MUCH.into());
        }
    }
    Ok((tokens, held))
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    prefixes: HashMap<String, String>,
    graph: Graph,
    /// what may still be held: each text comes out of it before it is, as one statement can hold any number of copies
    left: u64,
}

impl Parser {
    fn hold(&mut self, count: u64) -> Result<(), String> {
        self.left = self.left.checked_sub(count).ok_or(TOO_MUCH)?;
        Ok(())
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.at).cloned();
        self.at += 1;
        token
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn expect(&mut self, token: Token, what: &str) -> Result<(), String> {
        match self.next() {
            Some(found) if found == token => Ok(()),
            found => Err(format!("expected {what}, found {found:?}")),
        }
    }

    fn resolve(&self, name: &str) -> Result<String, String> {
        if name.starts_with("_:") {
            return Err("blank node subjects or objects are not supported".into());
        }
        let (prefix, local) = name
            .split_once(':')
            .ok_or_else(|| format!("'{name}' is neither an IRI nor a prefixed name"))?;
        let namespace = self
            .prefixes
            .get(prefix)
            .ok_or_else(|| format!("unknown prefix '{prefix}:'"))?;
        // it exists before its triple is charged, and one prefix can make any number of them
        if (namespace.len() + local.len()) as u64 > self.left {
            return Err(TOO_MUCH.into());
        }
        Ok([namespace.as_str(), local].concat())
    }

    fn iri(&mut self, what: &str) -> Result<String, String> {
        match self.next() {
            Some(Token::Iri(iri)) => Ok(iri),
            Some(Token::Name(name)) if name == "a" && what == "predicate" => Ok(RDF_TYPE.into()),
            Some(Token::Name(name)) => self.resolve(&name),
            Some(Token::Open('[')) => Err("blank node ([ … ]) is not supported".into()),
            Some(Token::Open('(')) => Err("collections are not supported".into()),
            found => Err(format!("expected {what}, found {found:?}")),
        }
    }

    fn object(&mut self) -> Result<Term, String> {
        match self.peek() {
            Some(Token::Str(_)) => {
                let Some(Token::Str(value)) = self.next() else {
                    unreachable!()
                };
                match self.peek() {
                    Some(Token::Carets) => {
                        self.at += 1;
                        let datatype = self.iri("datatype")?;
                        Ok(Term::Literal {
                            value,
                            datatype: Some(datatype),
                        })
                    }
                    Some(Token::LangTag) => {
                        self.at += 1;
                        Ok(Term::Literal { value, datatype: None })
                    }
                    _ => Ok(Term::Literal { value, datatype: None }),
                }
            }
            Some(Token::Name(name)) if name == "true" || name == "false" => {
                let value = name.clone();
                self.at += 1;
                Ok(Term::Literal {
                    value,
                    datatype: Some(format!("{XSD_NS}boolean")),
                })
            }
            Some(Token::Name(name)) if name.starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == '+') => {
                let value = name.clone();
                self.at += 1;
                let kind = if value.contains(['e', 'E']) {
                    "double"
                } else if value.contains('.') {
                    "decimal"
                } else {
                    "integer"
                };
                Ok(Term::Literal {
                    value,
                    datatype: Some(format!("{XSD_NS}{kind}")),
                })
            }
            _ => Ok(Term::Iri(self.iri("object")?)),
        }
    }

    fn statement(&mut self) -> Result<(), String> {
        match self.peek() {
            Some(Token::Directive(word)) if word == "prefix" => {
                self.at += 1;
                self.prefix_declaration()?;
                self.expect(Token::Dot, "'.' after @prefix")
            }
            Some(Token::Directive(word)) => Err(format!("@{word} is not supported")),
            Some(Token::Name(word)) if word.eq_ignore_ascii_case("prefix") => {
                self.at += 1;
                self.prefix_declaration()
            }
            _ => {
                let subject = self.iri("subject")?;
                // the index has a copy of its own
                if !self.graph.by_subject.contains_key(&subject) {
                    self.hold(LINE_COST + subject.len() as u64)?;
                }
                loop {
                    let predicate = self.iri("predicate")?;
                    loop {
                        let object = self.object()?;
                        self.hold(LINE_COST + (subject.len() + predicate.len()) as u64 + object.text_len())?;
                        self.graph.add(&subject, &predicate, object);
                        if self.peek() == Some(&Token::Comma) {
                            self.at += 1;
                        } else {
                            break;
                        }
                    }
                    // `;` may repeat and may stand before the final `.`
                    let mut more = false;
                    while self.peek() == Some(&Token::Semicolon) {
                        self.at += 1;
                        more = true;
                    }
                    if !more || self.peek() == Some(&Token::Dot) {
                        break;
                    }
                }
                self.expect(Token::Dot, "'.' at the end of a statement")
            }
        }
    }

    fn prefix_declaration(&mut self) -> Result<(), String> {
        let Some(Token::Name(name)) = self.next() else {
            return Err("expected a prefix name".into());
        };
        let prefix = name.strip_suffix(':').ok_or("a prefix name ends with ':'")?.to_string();
        let Some(Token::Iri(namespace)) = self.next() else {
            return Err("expected the prefix's IRI".into());
        };
        self.hold(LINE_COST + (prefix.len() + namespace.len()) as u64)?;
        self.prefixes.insert(prefix, namespace);
        Ok(())
    }
}

/// Parses the Turtle subset AFF4 containers use; anything else is an error naming it.
pub fn parse(text: &str) -> Result<Graph, String> {
    let mut unlimited = u64::MAX;
    parse_within(text, &mut unlimited)
}

/// Like `parse`, for what a container claims: takes what its graph holds in memory from `budget` as the graph grows, and
/// refuses what does not fit before it is held: a short text can make many lines, and each triple has a copy of the text
/// of its subject, its predicate and of any prefix. The tokens count only while they are there.
pub fn parse_within(text: &str, budget: &mut u64) -> Result<Graph, String> {
    let (tokens, held) = tokenize(text, *budget)?;
    let mut parser = Parser {
        tokens,
        at: 0,
        prefixes: HashMap::new(),
        graph: Graph::default(),
        left: *budget - held,
    };
    while parser.peek().is_some() {
        parser.statement()?;
    }
    *budget = parser.left + held;
    Ok(parser.graph)
}

/// The prefixes factum writes with.
pub fn factum_prefixes() -> [(&'static str, &'static str); 5] {
    [
        ("aff4", AFF4_NS),
        ("aff4l", AFF4L_NS),
        ("factum", super::FACTUM_NS),
        ("rdf", RDF_NS),
        ("xsd", XSD_NS),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{AFF4_NS, AFF4L_NS, RDF_NS, XSD_NS};

    const PREFIXES: [(&str, &str); 4] = [("aff4", AFF4_NS), ("aff4l", AFF4L_NS), ("rdf", RDF_NS), ("xsd", XSD_NS)];

    #[test]
    fn a_stray_closing_bracket_is_an_error_not_a_hang() {
        assert_eq!(parse("x> .").unwrap_err(), "unexpected '>'");
        assert_eq!(parse("<a> <b> > .").unwrap_err(), "unexpected '>'");
    }

    #[test]
    fn what_is_refused_in_a_budget_is_refused_before_it_is_held() {
        let text = "<a> <b> <c> .\n";
        // a triple and its subject, the two lines factum writes for it, the text of both, and the tokens meanwhile
        let graph = 2 * LINE_COST + 3 + 1;
        let tokens = 4 * TOKEN_COST + 3;
        let mut budget = graph + tokens;
        parse_within(text, &mut budget).unwrap();
        assert_eq!(budget, tokens);
        let mut budget = graph + tokens - 1;
        assert_eq!(parse_within(text, &mut budget).unwrap_err(), TOO_MUCH);
        // a few bytes make a token each
        let mut budget = 1 << 20;
        assert_eq!(parse_within(&";".repeat(1 << 19), &mut budget).unwrap_err(), TOO_MUCH);
    }

    #[test]
    fn tokens_count_for_their_text_while_they_are_held() {
        let text = format!("\"{}\" ", "x".repeat(1 << 16));
        assert_eq!(tokenize(&text.repeat(2), 1 << 16).unwrap_err(), TOO_MUCH);
        let (tokens, held) = tokenize(&text.repeat(2), (2 << 16) + 2 * TOKEN_COST).unwrap();
        assert_eq!((tokens.len(), held), (2, (2 << 16) + 2 * TOKEN_COST));
        // one step of the text can make two tokens, and the last step counts too
        assert_eq!(tokenize("xxx.", 2 * TOKEN_COST + 3).unwrap().1, 2 * TOKEN_COST + 3);
        assert_eq!(tokenize("xxx.", 2 * TOKEN_COST + 2).unwrap_err(), TOO_MUCH);
        // a directive keeps its word
        assert_eq!(tokenize("@xxx", TOKEN_COST + 3).unwrap().1, TOKEN_COST + 3);
        assert_eq!(tokenize("@xxx", TOKEN_COST + 2).unwrap_err(), TOO_MUCH);
    }

    #[test]
    fn text_counts_for_what_it_holds() {
        // a long literal
        let long = format!("<a> <b> \"{}\" .\n", "x".repeat(1 << 20));
        let mut budget = 1 << 20;
        assert_eq!(parse_within(&long, &mut budget).unwrap_err(), TOO_MUCH);
        let mut budget = 3 << 20;
        parse_within(&long, &mut budget).unwrap();
        assert!(budget <= 2 << 20, "{budget}");
        // a long subject, which every triple of a statement holds a copy of
        let subject = "s".repeat(1 << 16);
        let triples = "<b> <c> ; ".repeat(1 << 10);
        let repeated = format!("<{subject}> {triples} <b> <c> .\n");
        let mut budget = 16 << 20;
        assert_eq!(parse_within(&repeated, &mut budget).unwrap_err(), TOO_MUCH);
    }

    /// A token is held as it grows: one with no end is refused for its size, not for having none.
    #[test]
    fn a_token_stops_as_it_grows_not_at_its_end() {
        let long = "x".repeat(1 << 16);
        for text in [format!("\"{long}"), format!("'''{long}"), format!("<{long}")] {
            assert_eq!(tokenize(&text, 1 << 10).unwrap_err(), TOO_MUCH, "{}", &text[..4]);
            assert_ne!(tokenize(&text, 1 << 20).unwrap_err(), TOO_MUCH, "{}", &text[..4]);
        }
    }

    /// An expansion exists before its triple is charged, so one that cannot fit is not made, and it holds only its text.
    #[test]
    fn an_expansion_that_does_not_fit_is_not_made() {
        let long = "s".repeat(1 << 16);
        let parser = |left| Parser {
            tokens: Vec::new(),
            at: 0,
            prefixes: HashMap::from([("p".to_string(), long.clone())]),
            graph: Graph::default(),
            left,
        };
        assert_eq!(parser(1 << 16).resolve("p:c").unwrap_err(), TOO_MUCH);
        let expanded = parser((1 << 16) + 1).resolve("p:c").unwrap();
        assert_eq!((expanded.len(), expanded.capacity()), ((1 << 16) + 1, (1 << 16) + 1));
    }

    /// One statement can hold any number of copies of a long text, so it stops as it grows, not at its end.
    #[test]
    fn a_statement_stops_where_its_triples_no_longer_fit() {
        let long = "s".repeat(1 << 16);
        let more = 1 << 10;
        let prefix = format!("@prefix p: <{long}> .\n");
        for text in [
            format!("<{long}> <b> <c>{} .\n", " , <c>".repeat(more)),
            format!("<{long}> <b> <c>{} .\n", " ; <b> <c>".repeat(more)),
            format!("<a> <{long}> <c>{} .\n", " , <c>".repeat(more)),
            format!("{prefix}<a> <b> p:c{} .\n", " , p:c".repeat(more)),
            format!("{prefix}<a> p:b <c>{} .\n", " ; p:b <c>".repeat(more)),
            format!("{prefix}<a> <b> \"x\"^^p:c{} .\n", " , \"x\"^^p:c".repeat(more)),
        ] {
            let budget = 1 << 20;
            let (tokens, held) = tokenize(&text, budget).unwrap();
            let mut parser = Parser {
                tokens,
                at: 0,
                prefixes: HashMap::new(),
                graph: Graph::default(),
                left: budget - held,
            };
            let stopped = loop {
                match parser.statement() {
                    Ok(()) => assert!(parser.peek().is_some(), "{}", &text[text.len() - 20..]),
                    Err(e) => break e,
                }
            };
            assert_eq!(stopped, TOO_MUCH);
            assert!(parser.graph.triples().len() <= 16, "{}", parser.graph.triples().len());
        }
    }

    /// A subject is held twice, in its triples and in the index; a prefix once more, beside what uses it.
    #[test]
    fn a_subject_and_a_prefix_count_for_their_own_text() {
        let long = "s".repeat(1 << 20);
        let cost = |text: &str| {
            let mut budget = 16 << 20;
            parse_within(text, &mut budget).unwrap();
            (16 << 20) - budget
        };
        let short = cost("<a> <b> <c> .\n");
        assert_eq!(cost(&format!("<{long}> <b> <c> .\n")) - short, (2 << 20) - 2);
        assert_eq!(
            cost(&format!("@prefix p: <{long}> .\n<a> <b> <c> .\n")) - short,
            LINE_COST + 1 + (1 << 20)
        );
    }

    #[test]
    fn characters_of_more_than_one_byte_are_read_whole() {
        let graph = parse("<aff4://ä> <p:ü> \"🦀\\u00e4\" . # kömment\n<b>\u{a0}<c> '''é'''.").unwrap();
        assert_eq!(graph.triples()[0].subject, "aff4://ä");
        assert_eq!(graph.triples()[0].object.value(), Some("🦀ä"));
        assert_eq!(graph.triples()[1].object.value(), Some("é"));
    }

    #[test]
    fn an_escape_is_hex_digits_only() {
        assert!(parse("<a\\u+041> <b> <c> .").is_err());
        assert!(parse("<a> <b> \"\\u+041\" .").is_err());
        assert!(parse("<a\\uä000> <b> <c> .").is_err());
    }

    fn typed(value: &str, datatype: &str) -> Term {
        Term::Literal {
            value: value.into(),
            datatype: Some(datatype.into()),
        }
    }

    fn sample() -> Graph {
        let mut graph = Graph::default();
        let file = "aff4://28617d0f-2ca1-47c0-82cb-4a8374029805";
        graph.add(file, &format!("{RDF_NS}type"), Term::Iri(format!("{AFF4_NS}FileImage")));
        graph.add(
            file,
            &format!("{RDF_NS}type"),
            Term::Iri(format!("{AFF4_NS}ZipSegment")),
        );
        graph.add(file, &format!("{AFF4_NS}size"), typed("23", &format!("{XSD_NS}long")));
        graph.add(
            file,
            &format!("{AFF4_NS}hash"),
            typed("47e2194cbeb3b83eef3c09d0cab3c4c1bab08736", &format!("{AFF4_NS}SHA1")),
        );
        graph.add(
            file,
            &format!("{AFF4L_NS}originalPathName"),
            Term::Literal {
                value: "Users/x/evil.exe".into(),
                datatype: None,
            },
        );
        graph.add(file, &format!("{AFF4_NS}stored"), Term::Iri("aff4://volume".into()));
        graph.add(
            "aff4://volume",
            &format!("{RDF_NS}type"),
            Term::Iri(format!("{AFF4_NS}ZipVolume")),
        );
        graph
    }

    #[test]
    fn round_trip_preserves_triples() {
        let graph = sample();
        assert_eq!(parse(&write(&graph, &PREFIXES)).unwrap(), graph);
    }

    #[test]
    fn the_iris_factum_writes_stay_as_they_are() {
        let mut graph = sample();
        let iris = [
            "aff4://28617d0f-2ca1-47c0-82cb-4a8374029805/information.turtle",
            "https://www.ietf.org/rfc/rfc1950.txt",
            "https://factum.invalid/Schema/2026/#sourcePathRaw",
            "aff4://a/b%20c?d=e&f#g",
            "aff4://ü/ネコ",
        ];
        for iri in iris {
            graph.add(iri, iri, Term::Iri(iri.into()));
        }
        let text = write(&graph, &PREFIXES);
        for iri in iris {
            assert!(text.contains(&format!("<{iri}>")), "{text}");
        }
        assert_eq!(parse(&text).unwrap(), graph);
    }

    #[test]
    fn what_an_iri_cannot_hold_is_encoded() {
        let mut graph = Graph::default();
        graph.add(
            "aff4://s a<b>\"{c}|^`\\\n\u{7f}\u{85}\u{2028}",
            &format!("{AFF4_NS}p q"),
            Term::Iri("aff4://o>\n<aff4://forged> a <x".into()),
        );
        let text = write(&graph, &PREFIXES);
        let body: Vec<&str> = text.lines().skip_while(|l| !l.starts_with('<')).collect();
        assert_eq!(body.len(), 2, "{text}");
        assert_eq!(
            body[0],
            "<aff4://s%20a%3Cb%3E%22%7Bc%7D%7C%5E%60%5C%0A%7F%C2%85%E2%80%A8>"
        );
        assert_eq!(
            body[1],
            "    <http://aff4.org/Schema#p%20q> <aff4://o%3E%0A%3Caff4://forged%3E%20a%20%3Cx> ."
        );
        let graph = parse(&text).unwrap();
        assert_eq!(graph.triples().len(), 1);
        assert_eq!(
            graph.triples()[0].object,
            Term::Iri("aff4://o%3E%0A%3Caff4://forged%3E%20a%20%3Cx".into())
        );
    }

    #[test]
    fn escapes_in_iris_are_decoded() {
        let graph = parse("<aff4://\\u0061\\U00000062> <http://p/\\u00FC> <aff4://o> .").unwrap();
        assert_eq!(graph.triples()[0].subject, "aff4://ab");
        assert_eq!(graph.triples()[0].predicate, "http://p/ü");
    }

    #[test]
    fn what_no_iri_may_hold_is_refused_written_or_escaped() {
        for iri in [
            "<aff4://a b>",
            "<aff4://a\nb>",
            "<aff4://a{b>",
            "<aff4://a\\u0020b>",
            "<aff4://a\\u003Eb>",
            "<aff4://a\\u005Cb>",
            "<aff4://a\\nb>",
            "<aff4://a\\u00>",
            "<aff4://a\\uD800b>",
        ] {
            assert!(parse(&format!("{iri} <http://p> <aff4://o> .")).is_err(), "{iri}");
        }
        assert!(parse("<aff4://a").unwrap_err().contains("unterminated"));
    }

    #[test]
    fn write_is_one_triple_per_line() {
        let graph = sample();
        let text = write(&graph, &PREFIXES);
        assert_eq!(text, write(&graph, &PREFIXES));
        let body: Vec<&str> = text.lines().skip_while(|l| !l.starts_with('<')).collect();
        assert_eq!(body[0], "<aff4://28617d0f-2ca1-47c0-82cb-4a8374029805>");
        assert_eq!(body[1], "    a aff4:FileImage ;");
        assert_eq!(body[2], "    a aff4:ZipSegment ;");
        assert_eq!(body[3], "    aff4:size \"23\"^^xsd:long ;");
        assert_eq!(
            body[4],
            "    aff4:hash \"47e2194cbeb3b83eef3c09d0cab3c4c1bab08736\"^^aff4:SHA1 ;"
        );
        assert_eq!(body[5], "    aff4l:originalPathName \"Users/x/evil.exe\" ;");
        assert_eq!(body[6], "    aff4:stored <aff4://volume> .");
        assert_eq!(body[7], "");
        assert_eq!(body[8], "<aff4://volume>");
        assert_eq!(body[9], "    a aff4:ZipVolume .");
    }

    #[test]
    fn escapes_round_trip() {
        let mut graph = Graph::default();
        for (index, value) in [
            "say \"hi\"",
            "back\\slash",
            "two\nlines\r",
            "tab\there",
            "Jürgen ネコ",
            "bell\u{7}",
        ]
        .iter()
        .enumerate()
        {
            graph.add(
                "aff4://s",
                &format!("{AFF4_NS}p{index}"),
                Term::Literal {
                    value: value.to_string(),
                    datatype: None,
                },
            );
        }
        let text = write(&graph, &PREFIXES);
        assert!(text.lines().count() > 6 && !text.contains('\u{7}'));
        assert_eq!(parse(&text).unwrap(), graph);
    }

    // AFF4-L Standard v1.0, section 6.1 (the standard gives no prefixes for this block)
    const SECTION_6_1: &str = r#"@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
<aff4://28617d0f-2ca1-47c0-82cb-4a8374029805>
        a                        aff4:FileImage , aff4:Image , aff4:ZipSegment ;
        aff4:hash                "47e2194cbeb3b83eef3c09d0cab3c4c1bab08736"^^aff4:SHA1 , "f7c9a3c77792c010880c571bd2e7f7e7"^^aff4:MD5 ;
        aff4:lastWritten         "2020-09-06T23:36:22Z"^^xsd:dateTime ;
        aff4:size                "23"^^xsd:long .
"#;

    // section 9
    const SECTION_9: &str = r#"@prefix :      <aff4://7cbb47d0-b04c-42bc-8c04-87b7782739ad> .
@prefix rdf:   <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix aff4:  <http://aff4.org/Schema#> .
@prefix aff4l: <http://aff4.org/Schema/2022/#> .

:       a                  aff4:ZipVolume ;
        aff4l:imports     <aff4://7cbb47d0-b04c-42bc-8c04-87b7782739ad/information.turtle.2> ;
        aff4:stored        "Base-Linear_1.aff4" .

"#;

    // section 10.1
    const SECTION_10_1: &str = r#"@prefix :      <aff4://7cbb47d0-b04c-42bc-8c04-87b7782739ad> .
@prefix aff4:  <http://aff4.org/Schema#> .

:/information.turtle
      aff4:hash      "440ee6deee01195096991a015d8b6569b13f575546fb60411bcdea2c3e3b9b2f"^^aff4:SHA256 ;
      aff4:hash      "6dbb15c6a9a4c5e9d893a7cfca636bf3080e6b1a5259744d26cb0f5aef3c094cda4caadd1853573a5d5b39113e7cd7e0208f571a80bd1f8caee9d68f78d99db9"^^aff4:SHA512 .
"#;

    #[test]
    fn parses_standard_examples() {
        let graph = parse(SECTION_6_1).unwrap();
        let file = "aff4://28617d0f-2ca1-47c0-82cb-4a8374029805";
        assert_eq!(
            graph
                .subjects_of_type(&format!("{AFF4_NS}ZipSegment"))
                .collect::<Vec<_>>(),
            vec![file]
        );
        let hashes: Vec<&Term> = graph.objects(file, &format!("{AFF4_NS}hash")).collect();
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes[1],
            &typed("f7c9a3c77792c010880c571bd2e7f7e7", &format!("{AFF4_NS}MD5"))
        );

        let graph = parse(SECTION_9).unwrap();
        let volume = "aff4://7cbb47d0-b04c-42bc-8c04-87b7782739ad";
        // the example's aff4l namespace is http://; the lookup accepts it for the https one of section 4.1
        let imports: Vec<&Term> = graph.objects(volume, &format!("{AFF4L_NS}imports")).collect();
        assert_eq!(imports, vec![&Term::Iri(format!("{volume}/information.turtle.2"))]);

        let graph = parse(SECTION_10_1).unwrap();
        let turtle = format!("{volume}/information.turtle");
        let hashes: Vec<&Term> = graph.objects(&turtle, &format!("{AFF4_NS}hash")).collect();
        assert_eq!(
            hashes[0],
            &typed(
                "440ee6deee01195096991a015d8b6569b13f575546fb60411bcdea2c3e3b9b2f",
                &format!("{AFF4_NS}SHA256")
            )
        );
    }

    #[test]
    fn other_namespace_matches_same_local_name() {
        let text =
            format!("@prefix aff4l: <{AFF4L_NS}> .\n<aff4://f> a aff4l:FileImage ;\n    aff4l:lastWritten \"x\" .\n");
        let graph = parse(&text).unwrap();
        assert_eq!(graph.subjects_of_type(&format!("{AFF4_NS}FileImage")).count(), 1);
        assert_eq!(graph.objects("aff4://f", &format!("{AFF4_NS}lastWritten")).count(), 1);
    }

    #[test]
    fn literals_numbers_and_comments() {
        let text = "@prefix aff4: <http://aff4.org/Schema#> . # a comment\n\
                    PREFIX x: <http://x/>\n\
                    <aff4://s> aff4:n 42 ; aff4:b true ; aff4:l \"hallo\"@de ;\n\
                    aff4:long \"\"\"two\nlines\"\"\" ; aff4:q 'single' ; aff4:u \"\\u00fc\" ; x:o x:a.b .\n";
        let graph = parse(text).unwrap();
        let get = |p: &str| graph.objects("aff4://s", p).next().unwrap().clone();
        assert_eq!(
            get("http://aff4.org/Schema#n"),
            typed("42", &format!("{XSD_NS}integer"))
        );
        assert_eq!(
            get("http://aff4.org/Schema#b"),
            typed("true", &format!("{XSD_NS}boolean"))
        );
        assert_eq!(
            get("http://aff4.org/Schema#l"),
            Term::Literal {
                value: "hallo".into(),
                datatype: None
            }
        );
        assert_eq!(
            get("http://aff4.org/Schema#long"),
            Term::Literal {
                value: "two\nlines".into(),
                datatype: None
            }
        );
        assert_eq!(
            get("http://aff4.org/Schema#q"),
            Term::Literal {
                value: "single".into(),
                datatype: None
            }
        );
        assert_eq!(
            get("http://aff4.org/Schema#u"),
            Term::Literal {
                value: "ü".into(),
                datatype: None
            }
        );
        assert_eq!(get("http://x/o"), Term::Iri("http://x/a.b".into()));
    }

    #[test]
    fn line_separators_are_escaped() {
        // characters other tools treat as line breaks never appear raw, so one triple stays one line
        let mut graph = Graph::default();
        let value = "in\u{2028}voice\u{2029}x\u{85}y";
        graph.add(
            "aff4://s",
            &format!("{AFF4_NS}p"),
            Term::Literal {
                value: value.into(),
                datatype: None,
            },
        );
        let text = write(&graph, &PREFIXES);
        assert!(!text.contains(['\u{2028}', '\u{2029}', '\u{85}']), "{text:?}");
        assert!(text.contains("\\u2028"));
        assert_eq!(parse(&text).unwrap(), graph);
    }

    #[test]
    fn blank_nodes_are_refused() {
        let error = parse("@prefix aff4: <http://aff4.org/Schema#> .\n<aff4://s> aff4:p [ aff4:q 1 ] .\n").unwrap_err();
        assert!(error.contains("blank node"), "{error}");
        assert!(parse("_:b <http://p> <http://o> .").unwrap_err().contains("blank node"));
    }

    #[test]
    fn unknown_prefix_is_an_error() {
        assert!(parse("<aff4://s> nope:p <aff4://o> .").unwrap_err().contains("nope"));
    }
}
