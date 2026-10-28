//! A4 PDF report with the content of the HTML print variant: notes first, the verification part and the
//! expanded integrity appendix on their own pages. A small layout engine on top of a minimal PDF writer
//! with embedded TrueType fonts (Type0 / Identity-H with a ToUnicode map, so text stays searchable and
//! copyable). No external renderer: PDF export works on air-gapped machines without a browser or Qt.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use ttf_parser::{Face, GlyphId};

use super::html::{ALERT, evidence_cells, meta_rows, technical_rows};
use super::model::{ReportModel, grouped_findings, readable_utc, status_sentence, verification_summary};
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

#[derive(Debug, Clone, Copy)]
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

struct Writer {
    fonts: Vec<Font>,
    pages: Vec<String>,
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
        serialize(&self.fonts, &self.pages, title)
    }
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

fn serialize(fonts: &[Font], pages: &[String], title: &str) -> Vec<u8> {
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

    let mut kids = String::new();
    for content in pages {
        let page = objects.reserve();
        let stream = objects.reserve();
        let _ = write!(kids, "{page} 0 R ");
        objects.write(
            page,
            format!(
                "<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] \
                 /Resources << /Font << {font_refs}>> >> /Contents {stream} 0 R >>"
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
        pdf.paragraph(body, &item.text, 0.0);
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
}
