//! A4 PDF report with the content of the HTML print variant: notes first, the verification part and the
//! expanded integrity appendix on their own pages. A small layout engine on top of a minimal PDF writer
//! with embedded TrueType fonts (Type0 / Identity-H with a ToUnicode map, so text stays searchable and
//! copyable). No external renderer: PDF export works on air-gapped machines without a browser or Qt.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::{Cursor, Write as _};

use flate2::Compression;
use flate2::write::ZlibEncoder;
use image::{ImageReader, Limits};
use ttf_parser::{Face, GlyphId};

use super::html::{ALERT, evidence_cells, meta_rows, technical_rows};
use super::model::{ReportModel, grouped_findings, readable_utc, status_sentence, verification_summary};
use crate::images::{self, NoteImage};
use crate::markup::{self, Block, ImageTarget, Inline};
use crate::verifier::Level;

const SANS: &[u8] = include_bytes!("../../assets/fonts/AtkinsonHyperlegibleNext-Regular.ttf");
const SANS_BOLD: &[u8] = include_bytes!("../../assets/fonts/AtkinsonHyperlegibleNext-Bold.ttf");
const SANS_ITALIC: &[u8] = include_bytes!("../../assets/fonts/AtkinsonHyperlegibleNext-Italic.ttf");
const MONO: &[u8] = include_bytes!("../../assets/fonts/JetBrainsMono-Regular.ttf");

const PAGE_WIDTH: f32 = 595.28;
const PAGE_HEIGHT: f32 = 841.89;
const MARGIN_X: f32 = 56.0;
const MARGIN_TOP: f32 = 56.0;
const MARGIN_BOTTOM: f32 = 60.0;
const CONTENT_WIDTH: f32 = PAGE_WIDTH - 2.0 * MARGIN_X;
/// Nested lists and quotes stop moving right here, so deeply nested note text keeps a usable width.
const MAX_INDENT: f32 = CONTENT_WIDTH * 0.6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FontId {
    Sans = 0,
    Bold = 1,
    Italic = 2,
    Mono = 3,
}

type Rgb = (f32, f32, f32);

const fn rgb(hex: u32) -> Rgb {
    (
        ((hex >> 16) & 0xff) as f32 / 255.0,
        ((hex >> 8) & 0xff) as f32 / 255.0,
        (hex & 0xff) as f32 / 255.0,
    )
}

const TEXT: Rgb = rgb(0x1c1f24);
const SECONDARY: Rgb = rgb(0x454b54);
const MUTED: Rgb = rgb(0x5e646e);
const BORDER: Rgb = rgb(0xd3d0c8);
const CODE_BACKGROUND: Rgb = rgb(0xf3f2ee);
const FAIL: Rgb = rgb(0xb03a0c);

fn status_colors(level: Level) -> (Rgb, Rgb, Rgb) {
    // background, border, text
    match level {
        Level::Ok => (rgb(0xeef7f2), rgb(0xa9d8c4), rgb(0x00704f)),
        Level::Warn => (rgb(0xfbf4e6), rgb(0xe5c98f), rgb(0x8a5a00)),
        Level::Fail => (rgb(0xfbece6), rgb(0xe7a98f), FAIL),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Style {
    font: FontId,
    size: f32,
    color: Rgb,
    leading: f32,
}

impl Style {
    const fn new(font: FontId, size: f32, color: Rgb) -> Self {
        Self {
            font,
            size,
            color,
            leading: 1.4,
        }
    }

    fn line_height(&self) -> f32 {
        self.size * self.leading
    }
}

struct Font {
    face: Face<'static>,
    data: &'static [u8],
    name: &'static str,
    /// glyph id -> the character it was used for (for the ToUnicode map)
    used: BTreeMap<u16, char>,
}

impl Font {
    fn new(data: &'static [u8], name: &'static str) -> Self {
        Self {
            face: Face::parse(data, 0).expect("embedded fonts are valid"),
            data,
            name,
            used: BTreeMap::new(),
        }
    }

    fn scale(&self) -> f32 {
        1000.0 / self.face.units_per_em() as f32
    }

    fn advance(&self, glyph: u16) -> f32 {
        self.face.glyph_hor_advance(GlyphId(glyph)).unwrap_or(0) as f32 * self.scale()
    }
}

/// A run of glyphs in one font.
struct Run {
    font: FontId,
    glyphs: Vec<u16>,
}

/// Text in one style; `\n` forces a line break. An `image` span stands for the image it names, with the alt text as
/// its text where nothing better can be drawn.
#[derive(Debug, Clone)]
struct Span {
    style: Style,
    text: String,
    image: Option<ImageTarget>,
}

/// One line of a laid-out paragraph: fragments in their styles.
#[derive(Default)]
struct Line {
    frags: Vec<(Style, String)>,
    width: f32,
    /// the style that sets the line's height and baseline
    lead: Option<Style>,
}

impl Line {
    fn push(&mut self, style: Style, text: &str, width: f32) {
        match self.frags.last_mut() {
            Some((last, existing)) if *last == style => existing.push_str(text),
            _ => self.frags.push((style, text.to_string())),
        }
        self.width += width;
        self.touch(style);
    }

    fn touch(&mut self, style: Style) {
        if self.lead.is_none_or(|lead| style.line_height() > lead.line_height()) {
            self.lead = Some(style);
        }
    }
}

/// Pixels of a note image, ready for the PDF: 8 bit RGB and, when the image is not opaque, an 8 bit alpha mask.
struct PdfImage {
    width: u32,
    height: u32,
    rgb: Vec<u8>,
    alpha: Option<Vec<u8>>,
}

/// Decodes for display only; the stored bytes are never touched. `None` for data that does not decode (truncated,
/// corrupt, or too large to hold in memory).
fn decode(image: &NoteImage) -> Option<PdfImage> {
    let mut reader = ImageReader::new(Cursor::new(&image.bytes)).with_guessed_format().ok()?;
    let mut limits = Limits::default();
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    let decoded = reader.decode().ok()?;
    let (width, height) = (decoded.width(), decoded.height());
    if decoded.color().has_alpha() {
        // no copy of the pixels when the decoder already produced RGBA; rgb and alpha are split in one pass
        let rgba = decoded.into_rgba8().into_raw();
        let mut rgb = Vec::with_capacity(rgba.len() / 4 * 3);
        let mut alpha = Vec::with_capacity(rgba.len() / 4);
        for pixel in rgba.chunks_exact(4) {
            rgb.extend_from_slice(&pixel[..3]);
            alpha.push(pixel[3]);
        }
        drop(rgba);
        let opaque = alpha.iter().all(|a| *a == 255);
        return Some(PdfImage {
            width,
            height,
            rgb,
            alpha: (!opaque).then_some(alpha),
        });
    }
    Some(PdfImage {
        width,
        height,
        rgb: decoded.into_rgb8().into_raw(),
        alpha: None,
    })
}

struct Writer {
    fonts: Vec<Font>,
    pages: Vec<String>,
    /// the images drawn so far, each once; `/Im<index>` on the pages
    images: Vec<PdfImage>,
    /// file name (hash of the bytes) -> index in `images`, `None` when the image does not decode
    image_index: HashMap<String, Option<usize>>,
    /// the page drawing goes to
    current: usize,
    y: f32,
}

impl Writer {
    fn new() -> Self {
        let fonts = vec![
            Font::new(SANS, "AtkinsonHyperlegibleNext-Regular"),
            Font::new(SANS_BOLD, "AtkinsonHyperlegibleNext-Bold"),
            Font::new(SANS_ITALIC, "AtkinsonHyperlegibleNext-Italic"),
            Font::new(MONO, "JetBrainsMono-Regular"),
        ];
        let mut writer = Self {
            fonts,
            pages: Vec::new(),
            images: Vec::new(),
            image_index: HashMap::new(),
            current: 0,
            y: 0.0,
        };
        writer.new_page();
        writer
    }

    fn new_page(&mut self) {
        self.pages.push(String::new());
        self.current = self.pages.len() - 1;
        self.y = PAGE_HEIGHT - MARGIN_TOP;
    }

    fn page(&mut self) -> &mut String {
        &mut self.pages[self.current]
    }

    /// Starts a new page unless height still fits on this one.
    fn ensure(&mut self, height: f32) {
        if self.y - height < MARGIN_BOTTOM && self.y < PAGE_HEIGHT - MARGIN_TOP - 1.0 {
            self.new_page();
        }
    }

    fn space(&mut self, height: f32) {
        self.y -= height;
        if self.y < MARGIN_BOTTOM {
            self.new_page();
        }
    }

    /// The glyph for c in the style's font, falling back to the monospace font for symbols like ✓ ✗ ⚠.
    fn glyph(&self, font: FontId, c: char) -> (FontId, u16) {
        let c = if c == '\t' { ' ' } else { c };
        if let Some(glyph) = self.fonts[font as usize].face.glyph_index(c) {
            return (font, glyph.0);
        }
        if let Some(glyph) = self.fonts[FontId::Mono as usize].face.glyph_index(c) {
            return (FontId::Mono, glyph.0);
        }
        (font, 0)
    }

    fn char_width(&self, style: &Style, c: char) -> f32 {
        let (font, glyph) = self.glyph(style.font, c);
        self.fonts[font as usize].advance(glyph) * style.size / 1000.0
    }

    fn width(&self, style: &Style, text: &str) -> f32 {
        text.chars().map(|c| self.char_width(style, c)).sum()
    }

    /// Breaks text into lines that fit width: at spaces, inside words only when a word is too long.
    /// Newlines in the text are kept (like white-space: pre-wrap).
    fn wrap(&self, style: &Style, text: &str, width: f32) -> Vec<String> {
        let mut lines = Vec::new();
        for paragraph in text.replace("\r\n", "\n").replace('\r', "\n").split('\n') {
            let mut line = String::new();
            let mut line_width = 0.0;
            // words keep their trailing spaces, so the original spacing survives
            let mut words: Vec<String> = Vec::new();
            for c in paragraph.chars() {
                match words.last_mut() {
                    Some(word) if !(word.ends_with(' ') && c != ' ') => word.push(c),
                    _ => words.push(c.to_string()),
                }
            }
            for word in words {
                let word_width = self.width(style, &word);
                let visible_width = self.width(style, word.trim_end());
                if line_width + visible_width <= width || line.is_empty() && word_width <= width {
                    line.push_str(&word);
                    line_width += word_width;
                    continue;
                }
                if !line.is_empty() {
                    lines.push(std::mem::take(&mut line));
                    line_width = 0.0;
                }
                if visible_width <= width {
                    line.push_str(&word);
                    line_width = word_width;
                    continue;
                }
                // a word longer than the line (hashes, URLs): break it between characters
                for c in word.chars() {
                    let char_width = self.char_width(style, c);
                    if line_width + char_width > width && !line.is_empty() {
                        lines.push(std::mem::take(&mut line));
                        line_width = 0.0;
                    }
                    line.push(c);
                    line_width += char_width;
                }
            }
            lines.push(line);
        }
        lines
    }

    fn runs(&mut self, style: &Style, text: &str) -> Vec<Run> {
        let mut runs: Vec<Run> = Vec::new();
        for c in text.chars() {
            let (font, glyph) = self.glyph(style.font, c);
            self.fonts[font as usize]
                .used
                .entry(glyph)
                .or_insert(if c == '\t' { ' ' } else { c });
            match runs.last_mut() {
                Some(run) if run.font == font => run.glyphs.push(glyph),
                _ => runs.push(Run {
                    font,
                    glyphs: vec![glyph],
                }),
            }
        }
        runs
    }

    /// Draws one line of text with its baseline at y.
    fn draw_text(&mut self, style: &Style, text: &str, x: f32, baseline: f32) {
        let mut x = x;
        let runs = self.runs(style, text);
        let (r, g, b) = style.color;
        for run in runs {
            let hex: String = run.glyphs.iter().map(|glyph| format!("{glyph:04X}")).collect();
            let width: f32 = run
                .glyphs
                .iter()
                .map(|glyph| self.fonts[run.font as usize].advance(*glyph))
                .sum::<f32>()
                * style.size
                / 1000.0;
            let _ = writeln!(
                self.page(),
                "BT /F{} {:.2} Tf {r:.3} {g:.3} {b:.3} rg {x:.2} {baseline:.2} Td <{hex}> Tj ET",
                run.font as usize,
                style.size
            );
            x += width;
        }
    }

    fn fill_rect(&mut self, color: Rgb, x: f32, y: f32, width: f32, height: f32) {
        let (r, g, b) = color;
        let _ = writeln!(
            self.page(),
            "{r:.3} {g:.3} {b:.3} rg {x:.2} {y:.2} {width:.2} {height:.2} re f"
        );
    }

    fn stroke_rect(&mut self, color: Rgb, x: f32, y: f32, width: f32, height: f32) {
        let (r, g, b) = color;
        let _ = writeln!(
            self.page(),
            "{r:.3} {g:.3} {b:.3} RG 0.6 w {x:.2} {y:.2} {width:.2} {height:.2} re S"
        );
    }

    fn line(&mut self, color: Rgb, thickness: f32, x1: f32, y1: f32, x2: f32, y2: f32) {
        let (r, g, b) = color;
        let _ = writeln!(
            self.page(),
            "{r:.3} {g:.3} {b:.3} RG {thickness:.2} w {x1:.2} {y1:.2} m {x2:.2} {y2:.2} l S"
        );
    }

    /// A wrapped block of text at an indent; long blocks continue on the next page.
    fn paragraph(&mut self, style: Style, text: &str, indent: f32) {
        self.paragraph_with_background(style, text, indent, None);
    }

    fn paragraph_with_background(&mut self, style: Style, text: &str, indent: f32, background: Option<Rgb>) {
        let padding = if background.is_some() { 5.0 } else { 0.0 };
        let width = CONTENT_WIDTH - indent - 2.0 * padding;
        let lines = self.wrap(&style, text, width);
        let height = style.line_height();
        if let Some(color) = background {
            self.ensure(height + 2.0 * padding);
            self.fill_rect(
                color,
                MARGIN_X + indent,
                self.y - padding,
                CONTENT_WIDTH - indent,
                padding,
            );
            self.y -= padding;
        }
        for line in lines {
            self.ensure(height);
            if let Some(color) = background {
                self.fill_rect(
                    color,
                    MARGIN_X + indent,
                    self.y - height,
                    CONTENT_WIDTH - indent,
                    height,
                );
            }
            let baseline = self.y - style.size * 1.05;
            self.draw_text(&style, &line, MARGIN_X + indent + padding, baseline);
            self.y -= height;
        }
        if let Some(color) = background {
            self.fill_rect(
                color,
                MARGIN_X + indent,
                self.y - padding,
                CONTENT_WIDTH - indent,
                padding,
            );
            self.y -= padding;
        }
    }

    /// Draws spans as a wrapped block: words wrap across style borders without being split, a `\n` breaks the line.
    fn rich_paragraph(&mut self, spans: &[Span], indent: f32) {
        for line in self.rich_lines(spans, CONTENT_WIDTH - indent) {
            let Some(lead) = line.lead.or_else(|| spans.first().map(|span| span.style)) else {
                continue;
            };
            self.ensure(lead.line_height());
            let baseline = self.y - lead.size * 1.05;
            let mut x = MARGIN_X + indent;
            for (style, text) in &line.frags {
                self.draw_text(style, text, x, baseline);
                x += self.width(style, text);
            }
            self.y -= lead.line_height();
        }
    }

    /// Breaks spans into lines of at most width, like `wrap` but over styled text.
    fn rich_lines(&self, spans: &[Span], width: f32) -> Vec<Line> {
        enum Token {
            Word(Vec<(Style, String)>),
            Break(Style),
        }
        let mut tokens: Vec<Token> = Vec::new();
        for span in spans {
            for c in span.text.chars().filter(|c| *c != '\r') {
                if c == '\n' {
                    tokens.push(Token::Break(span.style));
                    continue;
                }
                // a word keeps its trailing spaces and ends where a non-space follows them
                match tokens.last_mut() {
                    Some(Token::Word(frags)) if c == ' ' || !frags.last().is_some_and(|f| f.1.ends_with(' ')) => {
                        match frags.last_mut() {
                            Some((style, text)) if *style == span.style => text.push(c),
                            _ => frags.push((span.style, c.to_string())),
                        }
                    }
                    _ => tokens.push(Token::Word(vec![(span.style, c.to_string())])),
                }
            }
        }
        let mut lines = Vec::new();
        let mut line = Line::default();
        for token in tokens {
            let frags = match token {
                Token::Break(style) => {
                    line.touch(style);
                    lines.push(std::mem::take(&mut line));
                    continue;
                }
                Token::Word(frags) => frags,
            };
            let word_width: f32 = frags.iter().map(|(style, text)| self.width(style, text)).sum();
            let (last_style, last_text) = frags.last().expect("a word has a character");
            let visible_width = word_width - self.width(last_style, &last_text[last_text.trim_end().len()..]);
            let push_word = |line: &mut Line| {
                for (style, text) in &frags {
                    line.push(*style, text, self.width(style, text));
                }
            };
            if line.width + visible_width <= width || line.frags.is_empty() && word_width <= width {
                push_word(&mut line);
                continue;
            }
            if !line.frags.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            if visible_width <= width {
                push_word(&mut line);
                continue;
            }
            // a word longer than the line (hashes, URLs): break it between characters
            for (style, text) in &frags {
                for c in text.chars() {
                    let char_width = self.char_width(style, c);
                    if line.width + char_width > width && !line.frags.is_empty() {
                        lines.push(std::mem::take(&mut line));
                    }
                    line.push(*style, c.encode_utf8(&mut [0; 4]), char_width);
                }
            }
        }
        lines.push(line);
        lines
    }

    /// Decodes an image once per distinct content. The key is the hash of the bytes, never the stored `sha256`.
    fn embed(&mut self, image: &NoteImage) -> Option<usize> {
        let key = image.file_name();
        if let Some(index) = self.image_index.get(&key) {
            return *index;
        }
        let index = decode(image).map(|decoded| {
            self.images.push(decoded);
            self.images.len() - 1
        });
        self.image_index.insert(key, index);
        index
    }

    /// Draws embedded image `index` at its natural size (96 dpi), shrunk to the content area.
    fn image(&mut self, index: usize, indent: f32) {
        let (pixel_width, pixel_height) = (self.images[index].width as f32, self.images[index].height as f32);
        let scale = (CONTENT_WIDTH - indent)
            .min(pixel_width * 0.75)
            .min((PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM) * pixel_width / pixel_height)
            / pixel_width;
        let (width, height) = (pixel_width * scale, pixel_height * scale);
        self.ensure(height);
        let (x, y) = (MARGIN_X + indent, self.y - height);
        let _ = writeln!(
            self.page(),
            "q {width:.2} 0 0 {height:.2} {x:.2} {y:.2} cm /Im{index} Do Q"
        );
        self.y -= height + 3.0;
    }

    /// A paragraph of inline content; images that can be shown are drawn between the lines around them.
    fn inlines(&mut self, inlines: &[Inline], images: &[NoteImage], style: Style, indent: f32) {
        let mut pending: Vec<Span> = Vec::new();
        for span in spans(inlines, style) {
            let text = match &span.image {
                None => {
                    pending.push(span);
                    continue;
                }
                Some(ImageTarget::External(url)) => format!("[external image {url} not loaded]"),
                Some(ImageTarget::Note(id)) => match images::find(images, id).filter(|image| image.is_embeddable()) {
                    None => format!("[image {id} missing]"),
                    Some(image) => match self.embed(image) {
                        None => format!("[image {id} could not be shown]"),
                        Some(index) => {
                            self.flush_spans(&mut pending, indent);
                            self.image(index, indent);
                            continue;
                        }
                    },
                },
            };
            pending.push(Span {
                style: span.style,
                text,
                image: None,
            });
        }
        self.flush_spans(&mut pending, indent);
    }

    fn flush_spans(&mut self, spans: &mut Vec<Span>, indent: f32) {
        // breaks around a drawn image are not content
        if let Some(first) = spans.first_mut() {
            first.text = first.text.trim_start_matches([' ', '\n']).to_string();
        }
        if let Some(last) = spans.last_mut() {
            last.text = last.text.trim_end_matches([' ', '\n']).to_string();
        }
        if spans.iter().any(|span| !span.text.is_empty()) {
            self.rich_paragraph(spans, indent);
        }
        spans.clear();
    }

    /// A note's Markdown: headings, lists, quotes, code blocks, images and styled text.
    fn markup(&mut self, text: &str, images: &[NoteImage], body: Style) {
        self.blocks(&markup::parse(text), images, body, 0.0);
    }

    fn blocks(&mut self, blocks: &[Block], images: &[NoteImage], body: Style, indent: f32) {
        let gap = body.size * 0.3;
        for block in blocks {
            match block {
                Block::Paragraph(content) => {
                    self.inlines(content, images, body, indent);
                    self.y -= gap;
                }
                // the report's own headings are 14 pt and larger, so a note's stay below them
                Block::Heading(level, content) => {
                    let size = body.size + [2.0, 1.0, 0.0][usize::from(level.saturating_sub(1).min(2))];
                    let style = Style {
                        font: FontId::Bold,
                        size,
                        ..body
                    };
                    self.ensure(size * 3.0);
                    self.y -= size * 0.4;
                    self.inlines(content, images, style, indent);
                    self.y -= gap;
                }
                Block::List { start, items } => {
                    let markers: Vec<String> = (0..items.len())
                        .map(|number| start.map_or("•".to_string(), |first| format!("{}.", first + number as u64)))
                        .collect();
                    let step = markers
                        .iter()
                        .map(|marker| self.width(&body, marker) + 4.0)
                        .fold(14.0, f32::max);
                    for (marker, item) in markers.iter().zip(items) {
                        self.ensure(body.line_height() * 1.5);
                        let baseline = self.y - body.size * 1.05;
                        self.draw_text(&body, marker, MARGIN_X + indent + 2.0, baseline);
                        self.blocks(item, images, body, (indent + step).min(MAX_INDENT));
                    }
                }
                Block::Quote(inner) => {
                    let quoted = Style {
                        color: SECONDARY,
                        ..body
                    };
                    let (first_page, top) = (self.current, self.y);
                    self.blocks(inner, images, quoted, (indent + 12.0).min(MAX_INDENT));
                    self.quote_bar(indent, first_page, top);
                }
                Block::Code(code) => {
                    let style = Style {
                        leading: 1.3,
                        ..Style::new(FontId::Mono, body.size * 0.85, TEXT)
                    };
                    self.paragraph_with_background(style, code, indent, Some(CODE_BACKGROUND));
                    self.y -= gap;
                }
            }
        }
    }

    /// The bar left of a quote that began at top on first_page and ends at the current position.
    fn quote_bar(&mut self, indent: f32, first_page: usize, top: f32) {
        let last_page = self.current;
        let end = self.y;
        for page in first_page..=last_page {
            let from = if page == first_page {
                top
            } else {
                PAGE_HEIGHT - MARGIN_TOP
            };
            let to = if page == last_page { end } else { MARGIN_BOTTOM };
            if from > to {
                self.current = page;
                self.fill_rect(BORDER, MARGIN_X + indent + 2.0, to, 1.5, from - to);
            }
        }
        self.current = last_page;
    }

    fn heading(&mut self, text: &str, size: f32, rule: bool) {
        let style = Style::new(FontId::Bold, size, TEXT);
        self.ensure(size * 4.0); // a heading never ends a page alone
        self.space(size * 0.8);
        self.paragraph(style, text, 0.0);
        if rule {
            self.y -= 2.0;
            self.line(BORDER, 0.8, MARGIN_X, self.y, MARGIN_X + CONTENT_WIDTH, self.y);
        }
        self.y -= size * 0.4;
    }

    /// Two columns: a bold label and a wrapped value.
    fn meta_table(&mut self, rows: &[(&str, String)], font: FontId, size: f32) {
        let label_style = Style::new(FontId::Bold, size, SECONDARY);
        let value_style = Style::new(font, size, SECONDARY);
        let label_width = rows
            .iter()
            .map(|(label, _)| self.width(&label_style, label))
            .fold(0.0, f32::max)
            + 14.0;
        for (label, value) in rows {
            let lines = self.wrap(&value_style, value, CONTENT_WIDTH - label_width);
            self.ensure(value_style.line_height());
            let baseline = self.y - size * 1.05;
            self.draw_text(&label_style, label, MARGIN_X, baseline);
            for (index, line) in lines.iter().enumerate() {
                if index > 0 {
                    self.ensure(value_style.line_height());
                }
                let baseline = self.y - size * 1.05;
                self.draw_text(&value_style, line, MARGIN_X + label_width, baseline);
                self.y -= value_style.line_height();
            }
        }
    }

    /// A bordered table; each row keeps together on one page.
    fn grid(&mut self, header: &[&str], rows: &[Vec<String>], fractions: &[f32]) {
        let size = 9.0;
        let padding = 4.0;
        let header_style = Style::new(FontId::Bold, size, TEXT);
        let cell_style = Style::new(FontId::Sans, size, TEXT);
        let widths: Vec<f32> = fractions.iter().map(|f| f * CONTENT_WIDTH).collect();
        let header_cells: Vec<String> = header.iter().map(|h| h.to_string()).collect();
        let laid_out: Vec<(Style, Vec<Vec<String>>, f32)> = std::iter::once(&header_cells)
            .chain(rows.iter())
            .enumerate()
            .map(|(index, cells)| {
                let style = if index == 0 { header_style } else { cell_style };
                let wrapped: Vec<Vec<String>> = cells
                    .iter()
                    .zip(&widths)
                    .map(|(cell, width)| self.wrap(&style, cell, width - 2.0 * padding))
                    .collect();
                let line_count = wrapped.iter().map(Vec::len).max().unwrap_or(1);
                (style, wrapped, line_count as f32 * style.line_height() + 2.0 * padding)
            })
            .collect();
        for (index, (style, wrapped, height)) in laid_out.iter().enumerate() {
            let (style, height) = (*style, *height);
            // the header row never stays behind alone at the bottom of a page
            let keep = if index == 0 {
                laid_out.get(1).map_or(0.0, |row| row.2)
            } else {
                0.0
            };
            self.ensure(height + keep);
            let mut x = MARGIN_X;
            for (lines, width) in wrapped.iter().zip(&widths) {
                self.stroke_rect(BORDER, x, self.y - height, *width, height);
                for (number, line) in lines.iter().enumerate() {
                    let baseline = self.y - padding - number as f32 * style.line_height() - size * 1.05;
                    self.draw_text(&style, line, x + padding, baseline);
                }
                x += width;
            }
            self.y -= height;
        }
    }

    fn bullet(&mut self, style: Style, text: &str) {
        self.ensure(style.line_height());
        let baseline = self.y - style.size * 1.05;
        self.draw_text(&style, "•", MARGIN_X + 4.0, baseline);
        self.paragraph(style, text, 16.0);
    }

    fn status_box(&mut self, level: Level, text: &str) {
        let (background, border, color) = status_colors(level);
        let style = Style::new(
            if level == Level::Fail {
                FontId::Bold
            } else {
                FontId::Sans
            },
            10.0,
            color,
        );
        let padding = 7.0;
        let lines = self.wrap(&style, text, CONTENT_WIDTH - 2.0 * padding);
        let height = lines.len() as f32 * style.line_height() + 2.0 * padding;
        self.ensure(height);
        self.fill_rect(background, MARGIN_X, self.y - height, CONTENT_WIDTH, height);
        self.stroke_rect(border, MARGIN_X, self.y - height, CONTENT_WIDTH, height);
        for (number, line) in lines.iter().enumerate() {
            let baseline = self.y - padding - number as f32 * style.line_height() - style.size * 1.05;
            self.draw_text(&style, line, MARGIN_X + padding, baseline);
        }
        self.y -= height;
    }

    fn footer(&mut self, title: &str) {
        let style = Style::new(FontId::Sans, 8.0, MUTED);
        let count = self.pages.len();
        for number in 0..count {
            let text = format!("{title} · page {} of {count}", number + 1);
            let width = self.width(&style, &text);
            self.current = number;
            self.draw_text(&style, &text, PAGE_WIDTH - MARGIN_X - width, MARGIN_BOTTOM / 2.0);
        }
    }

    fn finish(self, title: &str) -> Vec<u8> {
        serialize(&self.fonts, &self.images, &self.pages, title)
    }
}

/// The inline content as styled spans: strong is bold, emphasis italic (bold stays bold), code monospace; a link is
/// its text followed by its address (unless the text is the address), never a clickable target; a line break is
/// `\n`. Images are spans that carry their target.
fn spans(inlines: &[Inline], body: Style) -> Vec<Span> {
    fn push(out: &mut Vec<Span>, style: Style, text: &str) {
        match out.last_mut() {
            Some(last) if last.style == style && last.image.is_none() => last.text.push_str(text),
            _ => out.push(Span {
                style,
                text: text.to_string(),
                image: None,
            }),
        }
    }
    fn walk(inlines: &[Inline], style: Style, out: &mut Vec<Span>) {
        for inline in inlines {
            match inline {
                Inline::Text(text) => push(out, style, text),
                Inline::Emphasis(inner) => {
                    let font = if style.font == FontId::Sans {
                        FontId::Italic
                    } else {
                        style.font
                    };
                    walk(inner, Style { font, ..style }, out);
                }
                Inline::Strong(inner) => {
                    let font = if matches!(style.font, FontId::Sans | FontId::Italic) {
                        FontId::Bold
                    } else {
                        style.font
                    };
                    walk(inner, Style { font, ..style }, out);
                }
                Inline::Code(code) => {
                    let mono = Style {
                        font: FontId::Mono,
                        size: style.size * 0.9,
                        ..style
                    };
                    push(out, mono, code);
                }
                Inline::LineBreak => push(out, style, "\n"),
                Inline::Link { text, url } => {
                    walk(text, style, out);
                    if markup::shows_address(text, url) {
                        push(out, style, &format!(" ({url})"));
                    }
                }
                Inline::Image { alt, target } => out.push(Span {
                    style,
                    text: alt.clone(),
                    image: Some(target.clone()),
                }),
            }
        }
    }
    let mut out = Vec::new();
    walk(inlines, body, &mut out);
    out
}

fn compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("writing to memory");
    encoder.finish().expect("writing to memory")
}

fn utf16_hex(text: &str) -> String {
    let mut hex = String::from("FEFF");
    for unit in text.encode_utf16() {
        let _ = write!(hex, "{unit:04X}");
    }
    hex
}

struct Objects {
    out: Vec<u8>,
    offsets: Vec<usize>,
}

impl Objects {
    fn reserve(&mut self) -> usize {
        self.offsets.push(0);
        self.offsets.len()
    }

    fn write(&mut self, id: usize, body: &[u8]) {
        self.offsets[id - 1] = self.out.len();
        self.out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        self.out.extend_from_slice(body);
        self.out.extend_from_slice(b"\nendobj\n");
    }

    fn stream(&mut self, id: usize, dictionary: &str, data: &[u8]) {
        let compressed = compress(data);
        let mut body = format!(
            "<< {dictionary} /Filter /FlateDecode /Length {} >>\nstream\n",
            compressed.len()
        )
        .into_bytes();
        body.extend_from_slice(&compressed);
        body.extend_from_slice(b"\nendstream");
        self.write(id, &body);
    }
}

fn to_unicode(used: &BTreeMap<u16, char>) -> String {
    let mut cmap = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
         /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
         /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    let entries: Vec<_> = used.iter().collect();
    for chunk in entries.chunks(100) {
        let _ = writeln!(cmap, "{} beginbfchar", chunk.len());
        for (glyph, c) in chunk {
            let mut buffer = [0u16; 2];
            let units: String = c.encode_utf16(&mut buffer).iter().map(|u| format!("{u:04X}")).collect();
            let _ = writeln!(cmap, "<{glyph:04X}> <{units}>");
        }
        cmap.push_str("endbfchar\n");
    }
    cmap.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    cmap
}

fn serialize(fonts: &[Font], images: &[PdfImage], pages: &[String], title: &str) -> Vec<u8> {
    let mut objects = Objects {
        out: b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec(),
        offsets: Vec::new(),
    };
    let catalog = objects.reserve();
    let pages_id = objects.reserve();
    let info = objects.reserve();

    let mut font_refs = String::new();
    for (index, font) in fonts.iter().enumerate() {
        if font.used.is_empty() {
            continue;
        }
        let (type0, cid, descriptor, file, unicode) = (
            objects.reserve(),
            objects.reserve(),
            objects.reserve(),
            objects.reserve(),
            objects.reserve(),
        );
        let _ = write!(font_refs, "/F{index} {type0} 0 R ");
        let face = &font.face;
        let scale = font.scale();
        let bbox = face.global_bounding_box();
        let widths: String = font
            .used
            .keys()
            .map(|glyph| format!("{glyph} [{:.0}]", font.advance(*glyph)))
            .collect::<Vec<_>>()
            .join(" ");
        let fixed = face.is_monospaced();
        objects.write(
            type0,
            format!(
                "<< /Type /Font /Subtype /Type0 /BaseFont /{} /Encoding /Identity-H /DescendantFonts [{cid} 0 R] /ToUnicode {unicode} 0 R >>",
                font.name
            )
            .as_bytes(),
        );
        objects.write(
            cid,
            format!(
                "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /{} /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> \
                 /FontDescriptor {descriptor} 0 R /CIDToGIDMap /Identity /DW 1000 /W [{widths}] >>",
                font.name
            )
            .as_bytes(),
        );
        objects.write(
            descriptor,
            format!(
                "<< /Type /FontDescriptor /FontName /{} /Flags {} /FontBBox [{:.0} {:.0} {:.0} {:.0}] /ItalicAngle {:.0} \
                 /Ascent {:.0} /Descent {:.0} /CapHeight {:.0} /StemV 80 /FontFile2 {file} 0 R >>",
                font.name,
                if fixed { 5 } else { 4 },
                bbox.x_min as f32 * scale,
                bbox.y_min as f32 * scale,
                bbox.x_max as f32 * scale,
                bbox.y_max as f32 * scale,
                face.italic_angle(),
                face.ascender() as f32 * scale,
                face.descender() as f32 * scale,
                face.capital_height().unwrap_or(face.ascender()) as f32 * scale,
            )
            .as_bytes(),
        );
        objects.stream(file, &format!("/Length1 {}", font.data.len()), font.data);
        objects.stream(unicode, "", to_unicode(&font.used).as_bytes());
    }

    let mut xobjects = String::new();
    for (index, image) in images.iter().enumerate() {
        let id = objects.reserve();
        let mask = image.alpha.as_ref().map(|_| objects.reserve());
        let _ = write!(xobjects, "/Im{index} {id} 0 R ");
        let size = format!("/Width {} /Height {} /BitsPerComponent 8", image.width, image.height);
        let smask = mask.map(|mask| format!(" /SMask {mask} 0 R")).unwrap_or_default();
        objects.stream(
            id,
            &format!("/Type /XObject /Subtype /Image {size} /ColorSpace /DeviceRGB{smask}"),
            &image.rgb,
        );
        if let (Some(mask), Some(alpha)) = (mask, &image.alpha) {
            objects.stream(
                mask,
                &format!("/Type /XObject /Subtype /Image {size} /ColorSpace /DeviceGray"),
                alpha,
            );
        }
    }
    let xobjects = if xobjects.is_empty() {
        String::new()
    } else {
        format!(" /XObject << {xobjects}>>")
    };

    let mut kids = String::new();
    for content in pages {
        let page = objects.reserve();
        let stream = objects.reserve();
        let _ = write!(kids, "{page} 0 R ");
        objects.write(
            page,
            format!(
                "<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] \
                 /Resources << /Font << {font_refs}>>{xobjects} >> /Contents {stream} 0 R >>"
            )
            .as_bytes(),
        );
        objects.stream(stream, "", content.as_bytes());
    }
    objects.write(
        pages_id,
        format!("<< /Type /Pages /Kids [{kids}] /Count {} >>", pages.len()).as_bytes(),
    );
    objects.write(
        catalog,
        format!("<< /Type /Catalog /Pages {pages_id} 0 R >>").as_bytes(),
    );
    objects.write(
        info,
        format!(
            "<< /Title <{}> /Producer <{}> >>",
            utf16_hex(title),
            utf16_hex(&format!("factum {}", crate::VERSION))
        )
        .as_bytes(),
    );

    let xref = objects.out.len();
    let mut trailer = format!("xref\n0 {}\n0000000000 65535 f \n", objects.offsets.len() + 1);
    for offset in &objects.offsets {
        let _ = writeln!(trailer, "{offset:010} 00000 n ");
    }
    let _ = write!(
        trailer,
        "trailer\n<< /Size {} /Root {catalog} 0 R /Info {info} 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objects.offsets.len() + 1
    );
    objects.out.extend_from_slice(trailer.as_bytes());
    objects.out
}

/// The PDF report of a case.
pub fn render_pdf(model: &ReportModel) -> Vec<u8> {
    let (case, report) = (&model.case, &model.report);
    let overall = report.overall();
    let mut pdf = Writer::new();
    let body = Style::new(FontId::Sans, 11.0, TEXT);
    let small = Style::new(FontId::Sans, 9.0, MUTED);
    let aside = Style::new(FontId::Italic, 8.5, MUTED);

    pdf.paragraph(
        Style {
            leading: 1.2,
            ..Style::new(FontId::Bold, 20.0, TEXT)
        },
        &case.case_name,
        0.0,
    );
    pdf.space(6.0);
    pdf.meta_table(&meta_rows(model), FontId::Sans, 9.5);
    pdf.space(8.0);
    pdf.status_box(overall, &format!("{overall} — {}", status_sentence(report)));

    let notes = model.notes();
    pdf.heading(&format!("Notes ({})", notes.len()), 14.0, true);
    if notes.is_empty() {
        pdf.paragraph(body, "No notes.", 0.0);
    }
    for item in notes {
        pdf.ensure(small.line_height() + body.line_height() * 2.0);
        pdf.space(6.0);
        let mut head = readable_utc(Some(&item.origin_created_utc));
        if let Some(evidence) = &item.evidence {
            head += &format!(" · {evidence}");
        }
        pdf.paragraph(
            Style {
                font: FontId::Bold,
                color: SECONDARY,
                ..small
            },
            &head,
            0.0,
        );
        pdf.space(2.0);
        pdf.markup(&item.text, &item.images, body);
        if item.status == Level::Fail {
            pdf.paragraph(Style::new(FontId::Bold, 9.5, FAIL), ALERT, 0.0);
        }
        let mut asides = Vec::new();
        if let Some(note) = item.correction_note() {
            asides.push(note);
        }
        if !item.labels.is_empty() {
            asides.push(format!("Labels (not signed): {}", item.labels.join(", ")));
        }
        asides.push(format!("Note #{}", item.origin_id));
        pdf.paragraph(aside, &asides.join(" · "), 0.0);
        pdf.space(5.0);
        pdf.line(rgb(0xe8e6e0), 0.5, MARGIN_X, pdf.y, MARGIN_X + CONTENT_WIDTH, pdf.y);
    }

    pdf.heading("Evidence", 14.0, true);
    if model.evidence.is_empty() {
        pdf.paragraph(body, "No evidence items.", 0.0);
    } else {
        let rows: Vec<Vec<String>> = model
            .evidence
            .iter()
            .map(|item| evidence_cells(item).to_vec())
            .collect();
        pdf.grid(
            &["#", "Description", "Hash", "Added", "Deleted"],
            &rows,
            &[0.06, 0.28, 0.30, 0.18, 0.18],
        );
    }

    if !model.containers.is_empty() {
        pdf.heading("Containers", 14.0, true);
        for container in &model.containers {
            pdf.heading(&format!("#{} {}", container.id, container.name), 11.5, false);
            pdf.meta_table(&container.rows(), FontId::Sans, 9.5);
            pdf.space(4.0);
            if container.files.is_empty() {
                pdf.paragraph(body, "No files.", 0.0);
            } else {
                pdf.grid(
                    &["Path", "Size", "SHA-256"],
                    &container.file_cells(),
                    &[0.42, 0.12, 0.46],
                );
            }
        }
    }

    pdf.heading("Case activity", 14.0, true);
    for item in model.activity() {
        let flag = if item.status == Level::Fail { " ⚠ FAIL" } else { "" };
        pdf.bullet(
            Style::new(FontId::Sans, 9.5, SECONDARY),
            &format!("{} — {}{flag}", readable_utc(Some(&item.origin_created_utc)), item.text),
        );
    }

    // the technical part starts on its own page, so the notes read without it
    pdf.new_page();
    pdf.heading(&format!("Verification: {overall}"), 14.0, true);
    let mono = Style::new(FontId::Mono, 8.0, SECONDARY);
    pdf.paragraph(mono, &verification_summary(report), 0.0);
    pdf.space(4.0);
    for (level, message) in grouped_findings(report) {
        let color = match level {
            Level::Fail => FAIL,
            _ => SECONDARY,
        };
        pdf.bullet(Style::new(FontId::Sans, 9.0, color), &format!("{level} {message}"));
    }
    pdf.space(6.0);
    pdf.meta_table(&technical_rows(model), FontId::Mono, 8.0);

    pdf.heading("Integrity appendix", 14.0, true);
    pdf.paragraph(
        Style::new(FontId::Sans, 9.5, SECONDARY),
        "Every log entry in log order, including superseded versions of corrected notes.",
        0.0,
    );
    let code = Style {
        leading: 1.3,
        ..Style::new(FontId::Mono, 7.0, TEXT)
    };
    for item in &model.appendix {
        pdf.ensure(40.0);
        pdf.space(6.0);
        pdf.paragraph(
            Style::new(FontId::Bold, 10.0, TEXT),
            &format!("#{} (leaf {})", item.entry_id, item.leaf_index),
            0.0,
        );
        pdf.space(2.0);
        pdf.paragraph_with_background(code, &item.integrity_lines().join("\n"), 0.0, Some(CODE_BACKGROUND));
    }

    let title = format!("Case report {}", case.case_file);
    pdf.footer(&title);
    pdf.finish(&title)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::markup::{Block, Inline};

    #[test]
    fn wrap_breaks_long_words_and_keeps_newlines() {
        let writer = Writer::new();
        let style = Style::new(FontId::Mono, 10.0, TEXT);
        let lines = writer.wrap(&style, &format!("{}\nshort", "a".repeat(200)), 200.0);
        assert!(lines.len() >= 3);
        assert_eq!(lines.last().unwrap(), "short");
        assert!(lines.iter().all(|line| writer.width(&style, line) <= 200.5));
    }

    #[test]
    fn symbols_fall_back_to_the_monospace_font() {
        let writer = Writer::new();
        assert_eq!(writer.glyph(FontId::Sans, '✓').0, FontId::Mono);
        assert_eq!(writer.glyph(FontId::Sans, 'ü').0, FontId::Sans);
    }

    fn rgba_image(width: u32, height: u32, alpha: u8) -> NoteImage {
        let pixels: Vec<u8> = (0..width * height)
            .flat_map(|n| [(n % 12) as u8 * 20, 80, 160, alpha])
            .collect();
        NoteImage::from_rgba(width, height, &pixels).unwrap()
    }

    fn line_texts(lines: &[Line]) -> Vec<String> {
        lines
            .iter()
            .map(|line| line.frags.iter().map(|(_, text)| text.as_str()).collect())
            .collect()
    }

    #[test]
    fn rich_paragraph_wraps_across_styles() {
        let writer = Writer::new();
        let bold = Style::new(FontId::Bold, 11.0, TEXT);
        let regular = Style::new(FontId::Sans, 11.0, TEXT);
        // the first n where "start" + "end" no longer fits behind the prefix
        let mut prefix = String::new();
        while writer.width(&bold, &format!("{prefix}startend")) <= CONTENT_WIDTH {
            prefix += "w ";
        }
        assert!(writer.width(&bold, &format!("{prefix}start")) <= CONTENT_WIDTH);
        let spans = [
            Span {
                style: bold,
                text: format!("{prefix}start"),
                image: None,
            },
            Span {
                style: regular,
                text: "end".into(),
                image: None,
            },
        ];
        let lines = writer.rich_lines(&spans, CONTENT_WIDTH);
        // "startend" is one word, so it moves to the next line as a whole
        assert_eq!(line_texts(&lines), [prefix.clone(), "startend".to_string()]);
        let fonts: Vec<FontId> = lines[1].frags.iter().map(|(style, _)| style.font).collect();
        assert_eq!(fonts, [FontId::Bold, FontId::Sans]);
    }

    #[test]
    fn rich_lines_break_on_newlines_and_split_overlong_words() {
        let writer = Writer::new();
        let style = Style::new(FontId::Mono, 10.0, TEXT);
        let long = "a".repeat(200);
        let spans = [Span {
            style,
            text: format!("one\n{long}"),
            image: None,
        }];
        let lines = writer.rich_lines(&spans, 200.0);
        let texts = line_texts(&lines);
        assert_eq!(texts[0], "one");
        assert!(texts.len() >= 3 && texts[1..].concat() == long);
        assert!(lines.iter().all(|line| line.width <= 200.5));
    }

    #[test]
    fn spans_carry_styles_and_link_addresses() {
        let body = Style::new(FontId::Sans, 11.0, TEXT);
        let inlines = match markup::parse("**b** *i* `c` [l](https://x.test)").remove(0) {
            Block::Paragraph(inlines) => inlines,
            other => panic!("{other:?}"),
        };
        let spans = spans(&inlines, body);
        let text: String = spans.iter().map(|span| span.text.as_str()).collect();
        assert_eq!(text, "b i c l (https://x.test)");
        let font_of = |word: &str| {
            let span = spans.iter().find(|span| span.text.contains(word)).unwrap();
            span.style.font
        };
        assert_eq!(font_of("b"), FontId::Bold);
        assert_eq!(font_of("i"), FontId::Italic);
        assert_eq!(font_of("c"), FontId::Mono);
        assert_eq!(font_of("https://x.test"), FontId::Sans);
        // an address that is the link text is not repeated
        let same = match markup::parse("[https://x.test](https://x.test)").remove(0) {
            Block::Paragraph(inlines) => inlines,
            other => panic!("{other:?}"),
        };
        assert_eq!(spans_text(&same, body), "https://x.test");
    }

    fn spans_text(inlines: &[Inline], body: Style) -> String {
        spans(inlines, body).iter().map(|span| span.text.as_str()).collect()
    }

    #[test]
    fn nested_strong_in_emphasis_stays_bold() {
        let body = Style::new(FontId::Sans, 11.0, TEXT);
        for text in ["*a **b** c*", "**a *b* c**"] {
            let Block::Paragraph(inlines) = markup::parse(text).remove(0) else {
                panic!()
            };
            let spans = spans(&inlines, body);
            let b = spans.iter().find(|span| span.text.contains('b')).unwrap();
            assert_eq!(b.style.font, FontId::Bold, "{text}");
        }
    }

    #[test]
    fn markup_draws_bold_runs() {
        let mut writer = Writer::new();
        writer.markup("**b** a", &[], Style::new(FontId::Sans, 11.0, TEXT));
        let page = &writer.pages[writer.current];
        assert!(page.contains("/F1 ") && page.contains("/F0 "), "{page}");
    }

    #[test]
    fn markup_lays_out_blocks_downwards_and_across_pages() {
        let body = Style::new(FontId::Sans, 11.0, TEXT);
        let mut writer = Writer::new();
        let start = writer.y;
        writer.markup(
            "# Title\n\n- one\n  - two\n- three\n\n3. x\n\n> quoted\n\n```\ncode\n```",
            &[],
            body,
        );
        assert!(writer.y < start - 100.0 && writer.pages.len() == 1);
        let long = "- item\n".repeat(120);
        writer.markup(&format!("> {}", "quoted text\n> ".repeat(120)), &[], body);
        writer.markup(&long, &[], body);
        assert!(writer.pages.len() > 2);
    }

    #[test]
    fn truncated_images_do_not_decode() {
        let image = rgba_image(8, 8, 255);
        let decoded = decode(&image).unwrap();
        assert_eq!((decoded.width, decoded.height), (8, 8));
        assert!(decoded.alpha.is_none(), "an opaque image needs no mask");
        let truncated = NoteImage {
            bytes: image.bytes[..image.bytes.len() / 2].to_vec(),
            ..image
        };
        assert!(decode(&truncated).is_none());
    }

    #[test]
    fn images_are_stored_once_by_their_recomputed_hash() {
        let mut writer = Writer::new();
        let image = rgba_image(3, 2, 255);
        // the stored hash and id are untrusted: equal bytes are one image, whatever they claim
        let relabelled = NoteImage {
            sha256: "0".repeat(64),
            id: "000000000000".into(),
            ..image.clone()
        };
        assert_eq!(writer.embed(&image), writer.embed(&relabelled));
        assert_eq!(writer.images.len(), 1);
        // different bytes are different images even when they claim the same hash
        let other = NoteImage {
            sha256: image.sha256.clone(),
            ..rgba_image(2, 2, 255)
        };
        assert_ne!(writer.embed(&image), writer.embed(&other));
        assert_eq!(writer.images.len(), 2);
        // an undecodable image has no entry
        let broken = NoteImage {
            bytes: image.bytes[..20].to_vec(),
            ..image
        };
        assert_eq!(writer.embed(&broken), None);
        assert_eq!(writer.images.len(), 2);
    }

    #[test]
    fn images_are_scaled_to_the_content_and_get_a_mask_when_translucent() {
        let mut writer = Writer::new();
        let body = Style::new(FontId::Sans, 11.0, TEXT);
        let tiny = rgba_image(3, 2, 255);
        let wide = rgba_image(2000, 10, 128);
        let (tiny_ref, wide_ref) = (tiny.reference("t"), wide.reference("w"));
        writer.markup(&format!("{tiny_ref}\n\n{wide_ref}"), &[tiny, wide], body);
        let page = writer.pages[writer.current].clone();
        // 3 px wide is 2.25 pt, 2000 px is capped at the content width
        assert!(page.contains("2.25 0 0 1.50 "), "{page}");
        assert!(
            page.contains(&format!("{CONTENT_WIDTH:.2} 0 0 {:.2} ", CONTENT_WIDTH / 200.0)),
            "{page}"
        );
        let bytes = writer.finish("t");
        let text = String::from_utf8_lossy(&bytes);
        assert_eq!(text.matches("/Subtype /Image").count(), 3);
        assert_eq!(text.matches("/SMask").count(), 1);
        assert!(text.contains("/XObject << /Im0 "));
    }

    #[test]
    fn tall_images_fit_on_a_page() {
        let mut writer = Writer::new();
        let body = Style::new(FontId::Sans, 11.0, TEXT);
        let tall = rgba_image(100, 3000, 255);
        let reference = tall.reference("t");
        writer.markup(&reference, &[tall], body);
        assert_eq!(writer.pages.len(), 1);
        let page = &writer.pages[0];
        assert!(
            page.contains(&format!(" 0 0 {:.2} ", PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM)),
            "{page}"
        );
    }

    #[test]
    fn deep_nesting_keeps_text_and_images_on_the_page() {
        let mut writer = Writer::new();
        let body = Style::new(FontId::Sans, 11.0, TEXT);
        let image = rgba_image(30, 20, 255);
        let mut text = String::new();
        // as deep as markup keeps structure: 15 lists, 30 quotes (deeper is literal text)
        for level in 0..14 {
            text += &format!("{}- level {level}\n", "  ".repeat(level));
        }
        text += &format!("{}- {}\n", "  ".repeat(14), image.reference("deep"));
        let quotes = format!("{} deep quote {}", ">".repeat(30), image.reference("q"));
        writer.markup(&text, std::slice::from_ref(&image), body);
        writer.markup(&quotes, std::slice::from_ref(&image), body);
        let mut drawn = 0;
        for page in &writer.pages {
            for line in page.lines().filter(|line| line.ends_with(" Do Q")) {
                let numbers: Vec<f32> = line[2..].split(' ').filter_map(|n| n.parse().ok()).collect();
                let (width, height, x) = (numbers[0], numbers[3], numbers[4]);
                assert!(width > 0.0 && height > 0.0, "{line}");
                assert!(x >= MARGIN_X && x + width <= PAGE_WIDTH - MARGIN_X + 0.01, "{line}");
                drawn += 1;
            }
            // text starts inside the page too
            for line in page.lines().filter(|line| line.starts_with("BT ")) {
                let x: f32 = line
                    .split(" Td")
                    .next()
                    .unwrap()
                    .rsplit(' ')
                    .nth(1)
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!((MARGIN_X..PAGE_WIDTH - MARGIN_X).contains(&x), "{line}");
            }
        }
        assert_eq!(drawn, 2);
        let lines = writer.rich_lines(
            &[Span {
                style: body,
                text: "word ".repeat(10),
                image: None,
            }],
            CONTENT_WIDTH - MAX_INDENT,
        );
        assert!(lines.len() < 10, "the clamped width still holds several words per line");
    }

    #[test]
    fn a_note_nested_100_000_deep_renders() {
        for note in markup::deeply_nested_notes() {
            let mut writer = Writer::new();
            writer.markup(&note, &[], Style::new(FontId::Sans, 11.0, TEXT));
            assert!(!writer.pages[0].is_empty());
        }
    }

    /// A PNG whose header declares width x height with a tiny (invalid) body, the size of a decompression bomb.
    fn png_declaring(width: u32, height: u32) -> NoteImage {
        fn crc(data: &[u8]) -> u32 {
            let mut crc = !0u32;
            for byte in data {
                crc ^= u32::from(*byte);
                for _ in 0..8 {
                    crc = if crc & 1 == 1 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }
        fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
            out.extend((data.len() as u32).to_be_bytes());
            let body: Vec<u8> = kind.iter().chain(data).copied().collect();
            out.extend(&body);
            out.extend(crc(&body).to_be_bytes());
        }
        let mut header = Vec::new();
        header.extend(width.to_be_bytes());
        header.extend(height.to_be_bytes());
        header.extend([8, 6, 0, 0, 0]); // 8 bit RGBA
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        chunk(&mut bytes, b"IHDR", &header);
        chunk(&mut bytes, b"IDAT", &compress(&[0; 16]));
        chunk(&mut bytes, b"IEND", &[]);
        NoteImage::from_bytes(bytes, None).unwrap()
    }

    #[test]
    fn images_declaring_huge_dimensions_do_not_decode() {
        let started = std::time::Instant::now();
        assert!(decode(&png_declaring(100_000, 100_000)).is_none());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        // the helper itself builds readable files: a small declaration with too little data fails, but not by size
        assert!(decode(&png_declaring(4, 4)).is_none());
    }
}
