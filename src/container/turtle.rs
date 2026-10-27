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
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
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
    format!("<{iri}>")
}

/// Writes the graph: the prefixes, then each subject (in the order they first appear) with one triple per line.
pub fn write(graph: &Graph, prefixes: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (prefix, namespace) in prefixes {
        let _ = writeln!(out, "@prefix {prefix}: <{namespace}> .");
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
        let _ = write!(out, "\n<{subject}>\n");
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

fn tokenize(text: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    let delimiter = |c: char| c.is_whitespace() || ";,<>\"'()[]#".contains(c);
    while at < chars.len() {
        let c = chars[at];
        if c.is_whitespace() {
            at += 1;
        } else if c == '#' {
            while at < chars.len() && chars[at] != '\n' {
                at += 1;
            }
        } else if c == '<' {
            let end = (at + 1..chars.len())
                .find(|&i| chars[i] == '>')
                .ok_or("unterminated IRI")?;
            tokens.push(Token::Iri(chars[at + 1..end].iter().collect()));
            at = end + 1;
        } else if c == '"' || c == '\'' {
            let long = chars.get(at + 1) == Some(&c) && chars.get(at + 2) == Some(&c);
            at += if long { 3 } else { 1 };
            let mut value = String::new();
            loop {
                let Some(&ch) = chars.get(at) else {
                    return Err("unterminated string".into());
                };
                if long && ch == c && chars.get(at + 1) == Some(&c) && chars.get(at + 2) == Some(&c) {
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
                    let escaped = *chars.get(at + 1).ok_or("unterminated string")?;
                    at += 2;
                    match escaped {
                        't' => value.push('\t'),
                        'b' => value.push('\u{8}'),
                        'n' => value.push('\n'),
                        'r' => value.push('\r'),
                        'f' => value.push('\u{c}'),
                        '"' | '\'' | '\\' => value.push(escaped),
                        'u' | 'U' => {
                            let len = if escaped == 'u' { 4 } else { 8 };
                            let hex: String = chars.get(at..at + len).ok_or("bad \\u escape")?.iter().collect();
                            let code = u32::from_str_radix(&hex, 16).map_err(|_| "bad \\u escape")?;
                            value.push(char::from_u32(code).ok_or("bad \\u escape")?);
                            at += len;
                        }
                        other => return Err(format!("unknown escape \\{other}")),
                    }
                    continue;
                }
                value.push(ch);
                at += 1;
            }
            tokens.push(Token::Str(value));
        } else if c == '@' {
            let start = at + 1;
            at = start;
            while at < chars.len() && (chars[at].is_ascii_alphanumeric() || chars[at] == '-') {
                at += 1;
            }
            let word: String = chars[start..at].iter().collect();
            // after a string it is a language tag, otherwise a directive
            if matches!(tokens.last(), Some(Token::Str(_))) {
                tokens.push(Token::LangTag);
            } else {
                tokens.push(Token::Directive(word.to_ascii_lowercase()));
            }
        } else if c == '^' && chars.get(at + 1) == Some(&'^') {
            tokens.push(Token::Carets);
            at += 2;
        } else if c == ';' {
            tokens.push(Token::Semicolon);
            at += 1;
        } else if c == ',' {
            tokens.push(Token::Comma);
            at += 1;
        } else if c == '.' && chars.get(at + 1).is_none_or(|n| delimiter(*n)) {
            tokens.push(Token::Dot);
            at += 1;
        } else if "()[]".contains(c) {
            tokens.push(Token::Open(c));
            at += 1;
        } else {
            let start = at;
            while at < chars.len() && !delimiter(chars[at]) {
                at += 1;
            }
            let mut word: String = chars[start..at].iter().collect();
            // a name never ends with a dot: that one ends the statement
            let mut dots = 0;
            while word.ends_with('.') {
                word.pop();
                dots += 1;
            }
            tokens.push(Token::Name(word));
            tokens.extend(std::iter::repeat_n(Token::Dot, dots.min(1)));
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    prefixes: HashMap<String, String>,
    graph: Graph,
}

impl Parser {
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
        Ok(format!("{namespace}{local}"))
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
                loop {
                    let predicate = self.iri("predicate")?;
                    loop {
                        let object = self.object()?;
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
        self.prefixes.insert(prefix, namespace);
        Ok(())
    }
}

/// Parses the Turtle subset AFF4 containers use; anything else is an error naming it.
pub fn parse(text: &str) -> Result<Graph, String> {
    let mut parser = Parser {
        tokens: tokenize(text)?,
        at: 0,
        prefixes: HashMap::new(),
        graph: Graph::default(),
    };
    while parser.peek().is_some() {
        parser.statement()?;
    }
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
