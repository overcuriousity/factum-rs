//! Editing aids of the note field: a Markdown toolbar, images from the clipboard, files or a drop, and the
//! thumbnails of the images a note is about to be saved with.

use std::ops::Range;
use std::path::Path;

use egui::text::{CCursor, CCursorRange, CharIndex};
use egui::{Id, Sense, TextEdit, Vec2};

use super::widgets::IconButton;
use super::{icons, markup_view, theme};
use crate::error::{FactumError, Result};
use crate::images::{self, MAX_IMAGE_BYTES, NoteImage};

/// Thumbnails of images not yet saved are this high.
pub const THUMBNAIL_HEIGHT: f32 = 64.0;
const THUMBNAIL_MAX_WIDTH: f32 = 160.0;
/// What the strip of thumbnails takes below the editor.
pub const THUMBNAIL_STRIP: f32 = THUMBNAIL_HEIGHT + 22.0;
const IMAGE_EXTENSIONS: [&str; 5] = ["png", "jpg", "jpeg", "gif", "webp"];
/// Alt text of an image that came from the clipboard
const PASTED_ALT: &str = "screenshot";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Bold,
    Italic,
    Code,
    Link,
    Heading,
    List,
    Quote,
}

/// `text` with `format` applied to the `selection` (char indices), and the selection to show afterwards: what was
/// typed in as a placeholder, or the address of a link, is selected so typing replaces it.
pub fn apply(text: &str, selection: Range<usize>, format: Format) -> (String, Range<usize>) {
    let chars: Vec<char> = text.chars().collect();
    let (a, b) = (selection.start.min(chars.len()), selection.end.min(chars.len()));
    let (start, end) = (a.min(b), a.max(b));
    match format {
        Format::Bold => wrap(&chars, start, end, "**", "**", "bold"),
        Format::Italic => wrap(&chars, start, end, "*", "*", "italic"),
        Format::Code => wrap(&chars, start, end, "`", "`", "code"),
        Format::Link => link(&chars, start, end),
        Format::Heading => prefix_lines(&chars, start, end, "## ", false),
        Format::List => prefix_lines(&chars, start, end, "- ", true),
        Format::Quote => prefix_lines(&chars, start, end, "> ", true),
    }
}

fn splice(chars: &[char], start: usize, end: usize, middle: &str, close: &str) -> String {
    let before: String = chars[..start].iter().collect();
    let after: String = chars[end..].iter().collect();
    format!("{before}{middle}{close}{after}")
}

/// `open` and `close` around the selection, or around `placeholder` when nothing is selected; the inside is selected.
fn wrap(
    chars: &[char],
    start: usize,
    end: usize,
    open: &str,
    close: &str,
    placeholder: &str,
) -> (String, Range<usize>) {
    let selected: String = chars[start..end].iter().collect();
    let inside = if selected.is_empty() { placeholder } else { &selected };
    let from = start + open.chars().count();
    let text = splice(chars, start, end, &format!("{open}{inside}"), close);
    (text, from..from + inside.chars().count())
}

/// `[selection](url)` with the address selected; without a selection `[text](url)` with the text selected.
fn link(chars: &[char], start: usize, end: usize) -> (String, Range<usize>) {
    if start == end {
        return wrap(chars, start, end, "[", "](url)", "text");
    }
    let (text, label) = wrap(chars, start, end, "[", "](url)", "");
    let url = label.end + 2;
    (text, url..url + 3)
}

/// `prefix` at the start of the line holding `start`, and with `through` of every line up to the one holding `end`
/// (not the line a selection merely ends at the start of). The selection moves with the text.
fn prefix_lines(chars: &[char], start: usize, end: usize, prefix: &str, through: bool) -> (String, Range<usize>) {
    let last = if through && end > start && chars[end - 1] == '\n' {
        end - 1
    } else if through {
        end
    } else {
        start
    };
    let mut line = start;
    while line > 0 && chars[line - 1] != '\n' {
        line -= 1;
    }
    let mut starts = vec![line];
    while let Some(newline) = chars[line..].iter().position(|&c| c == '\n').map(|i| line + i) {
        if newline >= last {
            break;
        }
        line = newline + 1;
        starts.push(line);
    }
    let width = prefix.chars().count();
    let mut out = chars.to_vec();
    for &at in starts.iter().rev() {
        out.splice(at..at, prefix.chars());
    }
    (out.into_iter().collect(), start + width..end + starts.len() * width)
}

/// Inserts `snippet` before char index `at` (clamped to the text); returns the cursor after it.
pub fn insert(text: &mut String, at: usize, snippet: &str) -> usize {
    let (byte, at) = match text.char_indices().nth(at) {
        Some((byte, _)) => (byte, at),
        None => (text.len(), text.chars().count()),
    };
    text.insert_str(byte, snippet);
    at + snippet.chars().count()
}

/// Drops the image and every reference to it from the text: each place the Markdown shows it.
pub fn remove_image(text: &mut String, images: &mut Vec<NoteImage>, id: &str) {
    images.retain(|image| image.id != id);
    let url = format!("{}{id}", crate::images::SCHEME);
    for range in crate::markup::image_ranges(text, &url).into_iter().rev() {
        text.replace_range(range, "");
    }
}

impl Format {
    const ALL: [Format; 7] = [
        Format::Bold,
        Format::Italic,
        Format::Code,
        Format::Link,
        Format::Heading,
        Format::List,
        Format::Quote,
    ];

    fn icon(self) -> &'static str {
        match self {
            Format::Bold => icons::BOLD,
            Format::Italic => icons::ITALIC,
            Format::Code => icons::INLINE_CODE,
            Format::Link => icons::LINK,
            Format::Heading => icons::HEADING,
            Format::List => icons::LIST,
            Format::Quote => icons::QUOTE,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Format::Bold => "Bold",
            Format::Italic => "Italic",
            Format::Code => "Code",
            Format::Link => "Link",
            Format::Heading => "Heading",
            Format::List => "List",
            Format::Quote => "Quote",
        }
    }
}

// ---- the editor's selection

/// The selected chars of the field, or its end while it has never had a cursor.
fn selection(ctx: &egui::Context, editor_id: Id, text: &str) -> Range<usize> {
    let range = TextEdit::load_state(ctx, editor_id)
        .and_then(|state| state.cursor.char_range())
        .map(|range| (range.primary.index.0, range.secondary.index.0));
    match range {
        Some((a, b)) => a.min(b)..a.max(b),
        None => text.chars().count()..text.chars().count(),
    }
}

/// Selects the chars and gives the field the focus, so typing goes on there after a button. A field without the
/// focus drops a selection when it is drawn, and a click that began and ended within one frame takes the focus
/// away at the end of that frame: so the next frame, in [`toolbar`], sets the selection once more.
fn select(ctx: &egui::Context, editor_id: Id, range: Range<usize>) {
    set_selection(ctx, editor_id, range.clone());
    ctx.data_mut(|d| d.insert_temp(editor_id.with("select"), range));
    ctx.request_repaint();
}

fn set_selection(ctx: &egui::Context, editor_id: Id, range: Range<usize>) {
    let mut state = TextEdit::load_state(ctx, editor_id).unwrap_or_default();
    state.cursor.set_char_range(Some(CCursorRange::two(
        CCursor::new(CharIndex(range.start)),
        CCursor::new(CharIndex(range.end)),
    )));
    state.store(ctx, editor_id);
    ctx.memory_mut(|m| m.request_focus(editor_id));
}

fn format_selection(ctx: &egui::Context, editor_id: Id, text: &mut String, format: Format) {
    let (formatted, selected) = apply(text, selection(ctx, editor_id, text), format);
    *text = formatted;
    select(ctx, editor_id, selected);
}

// ---- images

/// Reads an image file; `read` gets its bytes. The size is checked first, so a huge file is not read at all.
/// Returns the image and its alt text, the file name without extension.
fn load(path: &Path, read: impl FnOnce() -> Result<Vec<u8>>) -> Result<(NoteImage, String)> {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_IMAGE_BYTES as u64) {
        return Err(FactumError::general("The image is larger than 20 MB."));
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
    let alt: String = path
        .file_stem()
        .map(|s| s.to_string_lossy().chars().filter(|c| !c.is_control()).collect())
        .unwrap_or_default();
    Ok((NoteImage::from_bytes(read()?, name)?, alt))
}

/// Puts the images into the note: each is attached and its reference goes in at the cursor, one per line.
fn add_images(
    ctx: &egui::Context,
    editor_id: Id,
    text: &mut String,
    images: &mut Vec<NoteImage>,
    added: Vec<(NoteImage, String)>,
) {
    if added.is_empty() {
        return;
    }
    let snippet: Vec<String> = added.iter().map(|(image, alt)| image.reference(alt)).collect();
    let cursor = insert(text, selection(ctx, editor_id, text).end, &snippet.join("\n"));
    for (image, _) in added {
        if !images.iter().any(|attached| attached.id == image.id) {
            images.push(image);
        }
    }
    select(ctx, editor_id, cursor..cursor);
}

/// The image of a paste: only when the integration found an image and no text on the clipboard
/// ([`egui::Event::PasteImage`]). The pixels are read from the clipboard again, with their alpha as it was copied,
/// where `read_clipboard` can; else they are the event's.
pub fn pasted_image(
    events: &[egui::Event],
    read_clipboard: impl FnOnce() -> Option<NoteImage>,
) -> Option<Result<NoteImage>> {
    let pasted = events.iter().find_map(|event| match event {
        egui::Event::PasteImage(image) => Some(image),
        _ => None,
    })?;
    Some(match read_clipboard() {
        Some(image) => Ok(image),
        None => {
            let [width, height] = pasted.size;
            let rgba: Vec<u8> = pasted.pixels.iter().flat_map(|c| c.to_srgba_unmultiplied()).collect();
            NoteImage::from_rgba(width as u32, height as u32, &rgba)
        }
    })
}

/// The image on the clipboard, `None` when it has text (that is pasted as text, as before) or no image.
#[cfg(not(test))]
pub fn clipboard_image() -> Option<NoteImage> {
    let mut clipboard = arboard::Clipboard::new().ok()?;
    if clipboard.get_text().is_ok_and(|text| !text.is_empty()) {
        return None;
    }
    let image = clipboard.get_image().ok()?;
    NoteImage::from_rgba(image.width as u32, image.height as u32, &image.bytes).ok()
}

/// Tests must never read the clipboard of whoever runs them.
#[cfg(test)]
pub fn clipboard_image() -> Option<NoteImage> {
    None
}

/// Files dropped on the window and an image pasted while the field `editor_id` has the focus go into the note.
/// Errors are for the person to see; the images that did load are added anyway.
pub fn handle_input(ctx: &egui::Context, editor_id: Id, text: &mut String, images: &mut Vec<NoteImage>) -> Result<()> {
    let mut error = None;
    let mut added = Vec::new();
    let dropped = ctx.input(|i| i.raw.dropped_files.clone());
    for file in &dropped {
        match load(file.path(), || file.bytes().map_err(FactumError::general)) {
            Ok(loaded) => added.push(loaded),
            Err(e) => error = error.or(Some(e)),
        }
    }
    if ctx.memory(|m| m.has_focus(editor_id)) {
        match ctx.input(|i| pasted_image(&i.events, clipboard_image)) {
            Some(Ok(image)) => added.push((image, PASTED_ALT.to_string())),
            Some(Err(e)) => error = error.or(Some(e)),
            None => {}
        }
    }
    add_images(ctx, editor_id, text, images, added);
    error.map_or(Ok(()), Err)
}

/// The buttons above the field `editor_id`: the formats of the selection, and an image from a file.
pub fn toolbar(ui: &mut egui::Ui, editor_id: Id, text: &mut String, images: &mut Vec<NoteImage>) -> Result<()> {
    let mut result = Ok(());
    if let Some(range) = ui.data_mut(|d| d.remove_temp::<Range<usize>>(editor_id.with("select"))) {
        set_selection(ui.ctx(), editor_id, range);
    }
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        for format in Format::ALL {
            if IconButton::new(format.icon(), format.name()).show(ui).clicked() {
                format_selection(ui.ctx(), editor_id, text, format);
            }
        }
        ui.add_space(4.0);
        if IconButton::new(icons::IMAGE, "Image…").show(ui).clicked() {
            result = insert_from_files(ui.ctx(), editor_id, text, images);
        }
    });
    result
}

fn insert_from_files(ctx: &egui::Context, editor_id: Id, text: &mut String, images: &mut Vec<NoteImage>) -> Result<()> {
    let Some(paths) = rfd::FileDialog::new()
        .add_filter("Images", &IMAGE_EXTENSIONS)
        .pick_files()
    else {
        return Ok(());
    };
    let mut error = None;
    let mut added = Vec::new();
    for path in &paths {
        match load(path, || std::fs::read(path).map_err(FactumError::from)) {
            Ok(loaded) => added.push(loaded),
            Err(e) => error = error.or(Some(e)),
        }
    }
    add_images(ctx, editor_id, text, images, added);
    error.map_or(Ok(()), Err)
}

// ---- thumbnails

/// Images the text does not show: their reference sits in code, is escaped or was edited. Saving would leave them
/// out ([`images::referenced_ids`]).
pub fn unshown<'a>(text: &str, images: &'a [NoteImage]) -> Vec<&'a NoteImage> {
    let shown = images::referenced_ids(text);
    images.iter().filter(|image| !shown.contains(&image.id)).collect()
}

/// Refuses a note that would silently lose an attached image.
pub fn check_shown(text: &str, images: &[NoteImage]) -> Result<()> {
    match unshown(text, images).first() {
        None => Ok(()),
        Some(image) => Err(FactumError::general(format!(
            "Image {} is not shown in the note: its reference is in code, escaped or changed. Fix the reference \
             or remove the image, so it is not left out.",
            label(image)
        ))),
    }
}

fn label(image: &NoteImage) -> String {
    image.name.clone().unwrap_or_else(|| image.id.clone())
}

/// The images that will be saved with the note, small, each with a button that takes it out (and its references).
/// One the text does not show is marked: it would not be saved.
pub fn thumbnails(ui: &mut egui::Ui, text: &mut String, images: &mut Vec<NoteImage>) {
    if images.is_empty() {
        return;
    }
    let unshown: Vec<String> = unshown(text, images).iter().map(|image| image.id.clone()).collect();
    let mut removed = None;
    egui::ScrollArea::horizontal()
        .id_salt("composer-thumbnails")
        .auto_shrink([false, true])
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for image in images.iter() {
                    if thumbnail(ui, image, !unshown.contains(&image.id)) {
                        removed = Some(image.id.clone());
                    }
                }
            });
        });
    if let Some(id) = removed {
        remove_image(text, images, &id);
    }
}

/// One thumbnail; true when its remove button was clicked.
fn thumbnail(ui: &mut egui::Ui, image: &NoteImage, shown: bool) -> bool {
    let p = *theme::current(ui.ctx());
    // pending images are not an entry's: they are cached under entry 0
    let texture = markup_view::texture(ui.ctx(), 0, image);
    let size = match &texture {
        Some(texture) => {
            let natural = texture.size_vec2();
            let scale = (THUMBNAIL_HEIGHT / natural.y.max(1.0)).min(THUMBNAIL_MAX_WIDTH / natural.x.max(1.0));
            natural * scale
        }
        None => Vec2::splat(THUMBNAIL_HEIGHT),
    };
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    let label = match shown {
        true => label(image),
        false => format!("{}: not shown in the note, will not be saved", label(image)),
    };
    match &texture {
        Some(texture) => egui::Image::new((texture.id(), size)).paint_at(ui, rect),
        None => {
            ui.painter().rect_filled(rect, 3.0, p.surface);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "?",
                egui::FontId::proportional(theme::NOTE_SIZE),
                p.muted,
            );
        }
    }
    let stroke = match shown {
        true => ui.visuals().widgets.inactive.bg_stroke,
        false => {
            ui.painter()
                .rect_filled(rect, 3.0, ui.visuals().window_fill().gamma_multiply(0.6));
            egui::Stroke::new(2.0, p.fail)
        }
    };
    ui.painter().rect_stroke(rect, 3.0, stroke, egui::StrokeKind::Inside);
    response.on_hover_text(label);
    let button = egui::Rect::from_min_size(rect.right_top() + egui::vec2(-24.0, 2.0), egui::vec2(22.0, 22.0));
    ui.painter()
        .rect_filled(button, 4.0, ui.visuals().window_fill().gamma_multiply(0.85));
    ui.scope_builder(egui::UiBuilder::new().max_rect(button), |ui| {
        IconButton::new(icons::CLOSE, "Remove image").show(ui).clicked()
    })
    .inner
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(shade: u8) -> NoteImage {
        NoteImage::from_rgba(2, 2, &[shade; 16]).unwrap()
    }

    #[test]
    fn apply_wraps_the_selection() {
        assert_eq!(apply("a b", 2..3, Format::Bold), ("a **b**".to_string(), 4..5));
        assert_eq!(apply("a b", 2..3, Format::Italic), ("a *b*".to_string(), 3..4));
        assert_eq!(apply("a b", 2..3, Format::Code), ("a `b`".to_string(), 3..4));
        // a reversed range is the same selection
        assert_eq!(
            apply("a b", Range { start: 3, end: 2 }, Format::Bold),
            ("a **b**".to_string(), 4..5)
        );
    }

    #[test]
    fn apply_counts_chars_not_bytes() {
        assert_eq!(apply("ä ö", 2..3, Format::Bold), ("ä **ö**".to_string(), 4..5));
        assert_eq!(apply("ä ö", 0..1, Format::Code), ("`ä` ö".to_string(), 1..2));
        // past the end is the end
        assert_eq!(apply("ä", 5..9, Format::Bold), ("ä**bold**".to_string(), 3..7));
    }

    #[test]
    fn apply_inserts_a_placeholder() {
        assert_eq!(apply("", 0..0, Format::Bold), ("**bold**".to_string(), 2..6));
        assert_eq!(apply("", 0..0, Format::Italic), ("*italic*".to_string(), 1..7));
        assert_eq!(apply("", 0..0, Format::Code), ("`code`".to_string(), 1..5));
        assert_eq!(apply("x", 0..1, Format::Link), ("[x](url)".to_string(), 4..7));
        assert_eq!(apply("", 0..0, Format::Link), ("[text](url)".to_string(), 1..5));
        assert_eq!(apply("ab", 1..1, Format::Bold), ("a**bold**b".to_string(), 3..7));
    }

    #[test]
    fn line_formats_prefix_every_line() {
        assert_eq!(apply("a\nb", 0..3, Format::List), ("- a\n- b".to_string(), 2..7));
        assert_eq!(apply("a\nb", 0..3, Format::Quote), ("> a\n> b".to_string(), 2..7));
        // the heading is for the cursor's line only
        assert_eq!(apply("a\nb", 0..3, Format::Heading), ("## a\nb".to_string(), 3..6));
        assert_eq!(apply("a\nb", 3..3, Format::Heading), ("a\n## b".to_string(), 6..6));
        // from the middle of a line the whole line is prefixed
        assert_eq!(apply("one\ntwo", 5..5, Format::List), ("one\n- two".to_string(), 7..7));
        // a selection ending at the start of a line leaves that line alone
        assert_eq!(apply("a\nb", 0..2, Format::List), ("- a\nb".to_string(), 2..4));
        assert_eq!(apply("", 0..0, Format::List), ("- ".to_string(), 2..2));
    }

    #[test]
    fn insert_puts_the_snippet_at_a_char_index() {
        let mut text = "äb".to_string();
        assert_eq!(insert(&mut text, 1, "ö"), 2);
        assert_eq!(text, "äöb");
        assert_eq!(insert(&mut text, 99, "!"), 4);
        assert_eq!(text, "äöb!");
    }

    #[test]
    fn remove_image_drops_its_references() {
        let (one, two) = (image(1), image(2));
        let mut text = format!(
            "a {} b {} c {}",
            one.reference("x"),
            one.reference("y"),
            two.reference("z")
        );
        let mut images = vec![one.clone(), two.clone()];
        remove_image(&mut text, &mut images, &one.id);
        assert_eq!(text, format!("a  b  c {}", two.reference("z")));
        assert_eq!(images, vec![two.clone()]);
        // an id that is not there changes nothing
        remove_image(&mut text, &mut images, "000000000000");
        assert_eq!(images, vec![two]);
    }

    #[test]
    fn remove_image_cuts_what_the_markdown_shows_as_that_image() {
        let (one, two) = (image(1), image(2));
        let id = &one.id;
        let cases = [
            (format!("x ![a [b] c](factum-image:{id}) y"), "x  y".to_string()),
            (format!("x ![a](factum-image:{id} \"t\") y"), "x  y".to_string()),
            (format!("x ![a](<factum-image:{id}>) y"), "x  y".to_string()),
            (
                format!("x ![a][r] y\n\n[r]: factum-image:{id}"),
                format!("x  y\n\n[r]: factum-image:{id}"),
            ),
            // the image in a link's text goes, the link stays
            (
                format!("[![a](factum-image:{id})](https://x)"),
                "[](https://x)".to_string(),
            ),
            // in a code span it is text, not the image: left alone
            (
                format!("`![a](factum-image:{id})`"),
                format!("`![a](factum-image:{id})`"),
            ),
            (
                format!("{} {}", one.reference("a"), two.reference("b")),
                format!(" {}", two.reference("b")),
            ),
        ];
        for (before, after) in cases {
            let mut text = before.clone();
            let mut images = vec![one.clone(), two.clone()];
            remove_image(&mut text, &mut images, id);
            assert_eq!(text, after, "{before}");
            assert_eq!(images, vec![two.clone()]);
        }
    }

    #[test]
    fn a_paste_without_an_image_event_gives_nothing() {
        let events = [egui::Event::Paste("text".into()), egui::Event::Copy];
        assert!(pasted_image(&events, || panic!("the clipboard is not read")).is_none());
    }

    #[test]
    fn a_pasted_image_is_read_from_the_clipboard_else_taken_from_the_event() {
        let pixels = egui::ColorImage::new([2, 2], vec![egui::Color32::from_rgb(10, 20, 30); 4]);
        let events = [egui::Event::PasteImage(std::sync::Arc::new(pixels))];
        let from_clipboard = image(9);
        let got = pasted_image(&events, || Some(from_clipboard.clone())).unwrap().unwrap();
        assert_eq!(got, from_clipboard);
        let got = pasted_image(&events, || None).unwrap().unwrap();
        assert_eq!(got.mime, "image/png");
        let decoded = ::image::load_from_memory(&got.bytes).unwrap().into_rgba8();
        assert_eq!(decoded.dimensions(), (2, 2));
        assert_eq!(decoded.get_pixel(0, 0).0, [10, 20, 30, 255]);
    }

    #[test]
    fn load_names_the_image_after_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("login page.png");
        let png = image(3).bytes;
        let (loaded, alt) = load(&path, || Ok(png.clone())).unwrap();
        assert_eq!(alt, "login page");
        assert_eq!(loaded.name.as_deref(), Some("login page.png"));
        assert_eq!(loaded.bytes, png);
        // a file that is no image, whatever its name says
        let err = load(&path, || Ok(b"just text".to_vec())).unwrap_err();
        assert_eq!(err.to_string(), "Only PNG, JPEG, GIF or WebP images can be added.");
    }

    #[test]
    fn load_does_not_read_a_file_over_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.png");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(MAX_IMAGE_BYTES as u64 + 1)
            .unwrap();
        let err = load(&path, || panic!("the file is not read")).unwrap_err();
        assert_eq!(err.to_string(), "The image is larger than 20 MB.");
    }
}
