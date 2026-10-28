//! The parsed form of a note's Markdown. Every view (log, HTML, Markdown, PDF) renders this one tree, so they agree on
//! what a note says. Only plain CommonMark is read; raw HTML and anything unsupported stay literal source text,
//! so a rendered note never shows less than, or something other than, what was signed.

use std::ops::Range;

use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag};

use crate::images::SCHEME;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Paragraph(Vec<Inline>),
    /// level 1 to 6
    Heading(u8, Vec<Inline>),
    /// an item's content is always blocks, also in tight lists
    List {
        start: Option<u64>,
        items: Vec<Vec<Block>>,
    },
    Quote(Vec<Block>),
    /// contents without the final newline
    Code(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inline {
    Text(String),
    Emphasis(Vec<Inline>),
    Strong(Vec<Inline>),
    Code(String),
    /// soft and hard breaks alike
    LineBreak,
    Link {
        text: Vec<Inline>,
        url: String,
    },
    Image {
        alt: String,
        target: ImageTarget,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageTarget {
    /// `factum-image:<id>`, resolved against the note's own images
    Note(String),
    /// any other address; never fetched
    External(String),
}

/// At most this many elements are open at once (a quote in a list in a quote ...; emphasis in a link): deeper
/// structure stays its literal source text, so no renderer recurses without bound.
pub const MAX_DEPTH: usize = 32;

/// An open container while walking the parser's events.
enum Frame {
    Root(Vec<Block>),
    Quote(Vec<Block>),
    List {
        start: Option<u64>,
        items: Vec<Vec<Block>>,
    },
    /// `pending` holds inline content of a tight item until a block follows or the item ends
    Item {
        blocks: Vec<Block>,
        pending: Vec<Inline>,
    },
    Paragraph(Vec<Inline>),
    Heading(u8, Vec<Inline>),
    Emphasis(Vec<Inline>),
    Strong(Vec<Inline>),
    Link {
        text: Vec<Inline>,
        url: String,
    },
    Image {
        alt: Vec<Inline>,
        url: String,
    },
    Code(String),
    /// raw HTML block, kept as its source lines
    Html(String),
}

impl Frame {
    /// Where inline content goes, for frames that take it.
    fn inlines(&mut self) -> Option<&mut Vec<Inline>> {
        match self {
            Frame::Item { pending, .. } => Some(pending),
            Frame::Paragraph(v)
            | Frame::Heading(_, v)
            | Frame::Emphasis(v)
            | Frame::Strong(v)
            | Frame::Link { text: v, .. }
            | Frame::Image { alt: v, .. } => Some(v),
            _ => None,
        }
    }
}

pub fn parse(text: &str) -> Vec<Block> {
    let mut stack = vec![Frame::Root(Vec::new())];
    // nesting depth inside an unsupported element whose events are dropped
    let mut skipping = 0usize;
    let mut events = Parser::new_ext(text, Options::empty()).into_offset_iter();
    for (event, range) in events.by_ref() {
        if skipping > 0 {
            match event {
                Event::Start(_) => skipping += 1,
                Event::End(_) => skipping -= 1,
                _ => {}
            }
            continue;
        }
        match event {
            // an item is never refused: its list is open already and takes nothing else
            Event::Start(tag) => match start_frame(&tag)
                .filter(|frame| matches!(frame, Frame::Item { .. }) || stack.len() <= MAX_DEPTH)
            {
                Some(frame) => stack.push(frame),
                None => {
                    skipping = 1;
                    literal(&mut stack, &text[range]);
                }
            },
            Event::End(_) => end_frame(&mut stack),
            Event::Text(s) => match stack.last_mut() {
                Some(Frame::Code(c) | Frame::Html(c)) => c.push_str(&s),
                _ => push_text(&mut stack, &s),
            },
            Event::Code(s) => push_inline(&mut stack, Inline::Code(s.into_string())),
            Event::SoftBreak | Event::HardBreak => push_inline(&mut stack, Inline::LineBreak),
            Event::Html(s) => match stack.last_mut() {
                Some(Frame::Html(c)) => c.push_str(&s),
                _ => literal(&mut stack, &s),
            },
            Event::InlineHtml(s) => literal_inline(&mut stack, &s),
            // rules and everything else a plain-CommonMark parse should not produce
            _ => literal(&mut stack, &text[range]),
        }
    }
    // the parser balances its events; this only guards against a surprise
    while stack.len() > 1 {
        end_frame(&mut stack);
    }
    let Some(Frame::Root(mut blocks)) = stack.pop() else {
        return Vec::new();
    };
    // the parser consumes link reference definitions without an event; show them, after everything else
    let mut spans: Vec<_> = events
        .reference_definitions()
        .iter()
        .map(|(_, def)| def.span.clone())
        .collect();
    spans.sort_by_key(|r| r.start);
    for span in spans {
        blocks.push(Block::Paragraph(text_lines(text[span].trim_end())));
    }
    blocks
}

fn start_frame(tag: &Tag) -> Option<Frame> {
    Some(match tag {
        Tag::Paragraph => Frame::Paragraph(Vec::new()),
        Tag::Heading { level, .. } => Frame::Heading(heading_level(*level), Vec::new()),
        Tag::BlockQuote(_) => Frame::Quote(Vec::new()),
        Tag::CodeBlock(_) => Frame::Code(String::new()),
        Tag::HtmlBlock => Frame::Html(String::new()),
        Tag::List(start) => Frame::List {
            start: *start,
            items: Vec::new(),
        },
        Tag::Item => Frame::Item {
            blocks: Vec::new(),
            pending: Vec::new(),
        },
        Tag::Emphasis => Frame::Emphasis(Vec::new()),
        Tag::Strong => Frame::Strong(Vec::new()),
        Tag::Link { dest_url, .. } => Frame::Link {
            text: Vec::new(),
            url: dest_url.to_string(),
        },
        Tag::Image { dest_url, .. } => Frame::Image {
            alt: Vec::new(),
            url: dest_url.to_string(),
        },
        _ => return None,
    })
}

fn heading_level(level: HeadingLevel) -> u8 {
    level as u8
}

fn end_frame(stack: &mut Vec<Frame>) {
    if stack.len() < 2 {
        return;
    }
    let Some(frame) = stack.pop() else { return };
    match frame {
        Frame::Root(_) => {}
        Frame::Quote(blocks) => push_block(stack, Block::Quote(blocks)),
        Frame::List { start, items } => push_block(stack, Block::List { start, items }),
        Frame::Item { mut blocks, pending } => {
            flush(&mut blocks, pending);
            if let Some(Frame::List { items, .. }) = stack.last_mut() {
                items.push(blocks);
            }
        }
        Frame::Paragraph(v) => push_block(stack, Block::Paragraph(v)),
        Frame::Heading(level, v) => push_block(stack, Block::Heading(level, v)),
        Frame::Emphasis(v) => push_inline(stack, Inline::Emphasis(v)),
        Frame::Strong(v) => push_inline(stack, Inline::Strong(v)),
        Frame::Link { text, url } => push_inline(stack, Inline::Link { text, url }),
        Frame::Image { alt, url } => {
            let target = match url.strip_prefix(SCHEME) {
                Some(id) => ImageTarget::Note(id.to_string()),
                None => ImageTarget::External(url),
            };
            push_inline(
                stack,
                Inline::Image {
                    alt: plain(&alt),
                    target,
                },
            );
        }
        Frame::Code(mut code) => {
            if code.ends_with('\n') {
                code.pop();
            }
            push_block(stack, Block::Code(code));
        }
        Frame::Html(source) => push_block(stack, Block::Paragraph(text_lines(source.trim_end()))),
    }
}

/// Turns a tight item's loose inline content into a paragraph ahead of the next block.
fn flush(blocks: &mut Vec<Block>, pending: Vec<Inline>) {
    if !pending.is_empty() {
        blocks.push(Block::Paragraph(pending));
    }
}

fn push_block(stack: &mut [Frame], block: Block) {
    match stack.last_mut() {
        Some(Frame::Root(blocks) | Frame::Quote(blocks)) => blocks.push(block),
        Some(Frame::Item { blocks, pending }) => {
            flush(blocks, std::mem::take(pending));
            blocks.push(block);
        }
        _ => {}
    }
}

fn push_inline(stack: &mut [Frame], inline: Inline) {
    match stack.last_mut().and_then(Frame::inlines) {
        Some(v) => append(v, inline),
        // inline content outside any inline container: keep it as a paragraph of its own
        None => push_block(stack, Block::Paragraph(vec![inline])),
    }
}

fn push_text(stack: &mut [Frame], s: &str) {
    push_inline(stack, Inline::Text(s.to_string()));
}

/// Adds `inline`, joining neighbouring text.
fn append(v: &mut Vec<Inline>, inline: Inline) {
    if let (Some(Inline::Text(last)), Inline::Text(s)) = (v.last_mut(), &inline) {
        last.push_str(s);
        return;
    }
    v.push(inline);
}

/// Inline source text kept as it is.
fn literal_inline(stack: &mut [Frame], source: &str) {
    for inline in text_lines(source.trim_end_matches(['\n', '\r'])) {
        push_inline(stack, inline);
    }
}

/// Source of a block-level element kept as it is: a paragraph of its own, or, inside an inline container,
/// the same text in line. A tight item takes it as a block so it never merges with the item's text.
fn literal(stack: &mut [Frame], source: &str) {
    let lines = text_lines(source.trim_end_matches(['\n', '\r']));
    match stack.last_mut() {
        Some(Frame::Item { .. }) | None => push_block(stack, Block::Paragraph(lines)),
        Some(frame) => match frame.inlines() {
            Some(v) => lines.into_iter().for_each(|i| append(v, i)),
            None => push_block(stack, Block::Paragraph(lines)),
        },
    }
}

/// Text with a `LineBreak` for each newline.
fn text_lines(s: &str) -> Vec<Inline> {
    let mut out = Vec::new();
    for (i, line) in s.split('\n').enumerate() {
        if i > 0 {
            out.push(Inline::LineBreak);
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        if !line.is_empty() {
            out.push(Inline::Text(line.to_string()));
        }
    }
    out
}

/// Where `text` has an image of the address `url`, as byte ranges of its source (`![alt](url)`, `![alt][ref]`, ...),
/// outermost only, in order.
pub fn image_ranges(text: &str, url: &str) -> Vec<Range<usize>> {
    let mut ranges: Vec<Range<usize>> = Vec::new();
    for (event, range) in Parser::new_ext(text, Options::empty()).into_offset_iter() {
        if let Event::Start(Tag::Image { dest_url, .. }) = event
            && dest_url.as_ref() == url
            && ranges.last().is_none_or(|last| range.start >= last.end)
        {
            ranges.push(range);
        }
    }
    ranges
}

/// Text content only; images count as their alt text.
pub fn plain(inlines: &[Inline]) -> String {
    flatten(inlines, false)
}

fn flatten(inlines: &[Inline], addresses: bool) -> String {
    let mut out = String::new();
    for inline in inlines {
        match inline {
            Inline::Text(s) | Inline::Code(s) => out.push_str(s),
            Inline::Emphasis(v) | Inline::Strong(v) => out.push_str(&flatten(v, addresses)),
            Inline::LineBreak => out.push(' '),
            Inline::Link { text, url } => {
                out.push_str(&flatten(text, addresses));
                if addresses && shows_address(text, url) {
                    out.push_str(&format!(" ({url})"));
                }
            }
            Inline::Image { alt, .. } => out.push_str(alt),
        }
    }
    out
}

/// Whether a renderer must print the address next to the link text.
pub fn shows_address(text: &[Inline], url: &str) -> bool {
    plain(text) != url
}

/// The whole note on one line of text, for list rows and the like. Links keep their address.
pub fn to_plain(text: &str) -> String {
    let mut parts = Vec::new();
    collect(&parse(text), &mut parts);
    parts.join(" ")
}

fn collect(blocks: &[Block], parts: &mut Vec<String>) {
    for block in blocks {
        match block {
            Block::Paragraph(v) | Block::Heading(_, v) => parts.push(flatten(v, true)),
            Block::List { items, .. } => items.iter().for_each(|item| collect(item, parts)),
            Block::Quote(inner) => collect(inner, parts),
            Block::Code(code) => parts.push(code.split_whitespace().collect::<Vec<_>>().join(" ")),
        }
    }
}

/// Notes of about 100,000 characters nested as deep as they go, for the renderers' tests.
#[cfg(test)]
pub fn deeply_nested_notes() -> Vec<String> {
    vec![
        format!("{} x", ">".repeat(100_000)),
        format!("{}x", "- ".repeat(50_000)),
        format!("{}x", "> 1. ".repeat(20_000)),
        format!("{}x{}", "*".repeat(50_000), "*".repeat(50_000)),
        format!("{}x{}", "![".repeat(25_000), "](u)".repeat(25_000)),
        format!("{}x{}", "**a ".repeat(25_000), " b**".repeat(25_000)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Inline {
        Inline::Text(s.to_string())
    }

    fn para(s: &str) -> Block {
        Block::Paragraph(vec![t(s)])
    }

    #[test]
    fn renders_the_supported_elements() {
        let tree = parse("# H\n\n*e* **s** `c`\n\n- a\n  - b\n\n> q\n\n```\nx\n```");
        assert_eq!(
            tree,
            vec![
                Block::Heading(1, vec![t("H")]),
                Block::Paragraph(vec![
                    Inline::Emphasis(vec![t("e")]),
                    t(" "),
                    Inline::Strong(vec![t("s")]),
                    t(" "),
                    Inline::Code("c".into()),
                ]),
                Block::List {
                    start: None,
                    items: vec![vec![
                        para("a"),
                        Block::List {
                            start: None,
                            items: vec![vec![para("b")]],
                        },
                    ]],
                },
                Block::Quote(vec![para("q")]),
                Block::Code("x".into()),
            ]
        );
    }

    #[test]
    fn heading_levels_and_ordered_lists() {
        assert_eq!(
            parse("###### six\n\n3. a\n4. b"),
            vec![
                Block::Heading(6, vec![t("six")]),
                Block::List {
                    start: Some(3),
                    items: vec![vec![para("a")], vec![para("b")]],
                },
            ]
        );
    }

    #[test]
    fn loose_and_tight_items_have_the_same_shape() {
        let loose = parse("- a\n\n- b");
        let tight = parse("- a\n- b");
        assert_eq!(loose, tight);
        assert_eq!(
            tight,
            vec![Block::List {
                start: None,
                items: vec![vec![para("a")], vec![para("b")]],
            }]
        );
    }

    #[test]
    fn soft_breaks_are_line_breaks() {
        assert_eq!(
            parse("a\nb"),
            vec![Block::Paragraph(vec![t("a"), Inline::LineBreak, t("b")])]
        );
        assert_eq!(
            parse("a  \nb"),
            vec![Block::Paragraph(vec![t("a"), Inline::LineBreak, t("b")])]
        );
    }

    #[test]
    fn raw_html_is_text() {
        assert_eq!(parse("<b>x</b>"), vec![para("<b>x</b>")]);
        assert_eq!(parse("<!-- c -->"), vec![para("<!-- c -->")]);
        assert_eq!(parse("a <i>b</i> c"), vec![Block::Paragraph(vec![t("a <i>b</i> c")])]);
        assert_eq!(
            parse("<div>\nx\n</div>"),
            vec![Block::Paragraph(vec![
                t("<div>"),
                Inline::LineBreak,
                t("x"),
                Inline::LineBreak,
                t("</div>"),
            ])]
        );
        assert_eq!(
            parse("> <script>\n> y"),
            vec![Block::Quote(vec![Block::Paragraph(vec![
                t("<script>"),
                Inline::LineBreak,
                t("y"),
            ])])]
        );
    }

    #[test]
    fn rules_and_unsupported_blocks_keep_their_source() {
        assert_eq!(parse("---"), vec![para("---")]);
        assert_eq!(parse("a\n\n***\n\nb"), vec![para("a"), para("***"), para("b")]);
        assert_eq!(
            parse("- a\n\n  ***"),
            vec![Block::List {
                start: None,
                items: vec![vec![para("a"), para("***")]],
            }]
        );
    }

    #[test]
    fn link_reference_definitions_stay_visible() {
        assert_eq!(
            parse("[a][r]\n\n[r]: https://x \"title\"\n[s]: https://y"),
            vec![
                Block::Paragraph(vec![Inline::Link {
                    text: vec![t("a")],
                    url: "https://x".into(),
                }]),
                para("[r]: https://x \"title\""),
                para("[s]: https://y"),
            ]
        );
        assert_eq!(parse("[r]: https://evil"), vec![para("[r]: https://evil")]);
    }

    #[test]
    fn rules_in_tight_items_stay_separate_blocks() {
        assert_eq!(
            parse("- a\n  ***\n  b"),
            vec![Block::List {
                start: None,
                items: vec![vec![para("a"), para("***"), para("b")]],
            }]
        );
        assert_eq!(
            parse("- a\n  ***"),
            vec![Block::List {
                start: None,
                items: vec![vec![para("a"), para("***")]],
            }]
        );
    }

    #[test]
    fn inline_html_in_a_tight_item_stays_in_the_text() {
        assert_eq!(
            parse("- a <i>b"),
            vec![Block::List {
                start: None,
                items: vec![vec![para("a <i>b")]],
            }]
        );
    }

    #[test]
    fn tags_are_not_headings() {
        assert_eq!(parse("#tag here"), vec![para("#tag here")]);
    }

    #[test]
    fn note_and_external_images() {
        assert_eq!(
            parse("![a b](factum-image:abc)"),
            vec![Block::Paragraph(vec![Inline::Image {
                alt: "a b".into(),
                target: ImageTarget::Note("abc".into()),
            }])]
        );
        assert_eq!(
            parse("![x](https://x/y.png)"),
            vec![Block::Paragraph(vec![Inline::Image {
                alt: "x".into(),
                target: ImageTarget::External("https://x/y.png".into()),
            }])]
        );
    }

    #[test]
    fn image_alt_is_the_text_of_its_description() {
        assert_eq!(
            parse("![a *b* `c`](factum-image:i)"),
            vec![Block::Paragraph(vec![Inline::Image {
                alt: "a b c".into(),
                target: ImageTarget::Note("i".into()),
            }])]
        );
    }

    #[test]
    fn links_keep_text_and_address() {
        assert_eq!(
            parse("[**a**](https://a/b)"),
            vec![Block::Paragraph(vec![Inline::Link {
                text: vec![Inline::Strong(vec![t("a")])],
                url: "https://a/b".into(),
            }])]
        );
        assert_eq!(
            parse("<https://a>"),
            vec![Block::Paragraph(vec![Inline::Link {
                text: vec![t("https://a")],
                url: "https://a".into(),
            }])]
        );
    }

    #[test]
    fn shows_address_only_when_it_differs() {
        let same = parse("[https://a](https://a)");
        let other = parse("[a](https://a)");
        let link = |b: &[Block]| match &b[0] {
            Block::Paragraph(i) => match &i[0] {
                Inline::Link { text, url } => (text.clone(), url.clone()),
                x => panic!("{x:?}"),
            },
            x => panic!("{x:?}"),
        };
        let (text, url) = link(&same);
        assert!(!shows_address(&text, &url));
        let (text, url) = link(&other);
        assert!(shows_address(&text, &url));
    }

    #[test]
    fn code_blocks_are_verbatim() {
        assert_eq!(
            parse("```\n# not a heading\n*x*\n```"),
            vec![Block::Code("# not a heading\n*x*".into())]
        );
        assert_eq!(parse("    a\n    b"), vec![Block::Code("a\nb".into())]);
        assert_eq!(parse("```\n```"), vec![Block::Code(String::new())]);
    }

    #[test]
    fn plain_text_and_empty_input() {
        assert_eq!(parse(""), Vec::<Block>::new());
        assert_eq!(parse("\n\n"), Vec::<Block>::new());
        assert_eq!(parse("héllo ✓"), vec![para("héllo ✓")]);
    }

    fn block_depth(blocks: &[Block]) -> usize {
        blocks
            .iter()
            .map(|block| match block {
                Block::Paragraph(v) | Block::Heading(_, v) => 1 + inline_depth(v),
                Block::List { items, .. } => 2 + items.iter().map(|item| block_depth(item)).max().unwrap_or(0),
                Block::Quote(inner) => 1 + block_depth(inner),
                Block::Code(_) => 1,
            })
            .max()
            .unwrap_or(0)
    }

    fn inline_depth(inlines: &[Inline]) -> usize {
        inlines
            .iter()
            .map(|inline| match inline {
                Inline::Emphasis(v) | Inline::Strong(v) | Inline::Link { text: v, .. } => 1 + inline_depth(v),
                _ => 0,
            })
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn deep_nesting_is_capped_and_the_rest_stays_text() {
        for note in deeply_nested_notes() {
            let tree = parse(&note);
            let depth = block_depth(&tree);
            assert!(depth <= MAX_DEPTH + 2, "{depth} for {}", &note[..20]);
            // what is not structure any more is its source: the innermost text is still there
            assert!(to_plain(&note).contains('x'), "{}", &note[..20]);
        }
        // up to the cap nothing changes
        let quote = parse(&format!("{}x", "> ".repeat(MAX_DEPTH - 1)));
        assert_eq!(block_depth(&quote), MAX_DEPTH);
        assert!(!to_plain(&format!("{}x", "> ".repeat(MAX_DEPTH - 1))).contains('>'));
        // one more and the innermost quote is its source
        assert!(to_plain(&format!("{}x", "> ".repeat(MAX_DEPTH + 1))).contains("> x"));
    }

    #[test]
    fn to_plain_flattens() {
        assert_eq!(to_plain("**a** ![s](factum-image:abc)"), "a s");
        assert_eq!(to_plain("# H\n\nx\ny\n\n- a\n- b\n\n```\nc\nd\n```"), "H x y a b c d");
        assert_eq!(
            to_plain("[t](https://u) [https://v](https://v)"),
            "t (https://u) https://v"
        );
    }
}
