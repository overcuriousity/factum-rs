//! A note's Markdown as egui widgets: the same tree [`markup::parse`] gives the reports, drawn as selectable text,
//! lists, quotes, code blocks and inline images. Nothing here opens or fetches anything: a link is its text and,
//! where it differs, its address in brackets, as copyable text.

use egui::text::{LayoutJob, TextFormat};
use egui::{
    Color32, CornerRadius, CursorIcon, FontFamily, FontId, Frame, Margin, Response, Sense, Stroke, TextureHandle,
};

use super::theme::{self, Palette};
use crate::images::{self, NoteImage};
use crate::markup::{self, Block, ImageTarget, Inline};

/// Images in the log are shown at most this high.
const MAX_IMAGE_HEIGHT: f32 = 400.0;

/// The size of an image scaled down to fit `max_side` (the GPU's texture limit), keeping its aspect ratio.
pub fn fit(size: [usize; 2], max_side: usize) -> [usize; 2] {
    let longest = size[0].max(size[1]);
    if longest <= max_side {
        return size;
    }
    let scale = |side: usize| ((side as f64 * max_side as f64 / longest as f64).round() as usize).max(1);
    [scale(size[0]), scale(size[1])]
}

/// Textures are dropped when no frame drew them for this many seconds of input time.
const KEEP_SECONDS: f64 = 30.0;

/// What is known about one picture of one entry, and when a frame last needed it.
struct Slot {
    /// the size it is shown at before scaling to the card: `Some(None)` when its header does not read
    size: Option<Option<[usize; 2]>>,
    /// the decoded picture: `Some(None)` when it does not decode
    texture: Option<Option<TextureHandle>>,
    last_used: f64,
}

type Cache = std::collections::HashMap<(i64, String), Slot>;

/// The session's pictures, in the context's temporary data.
fn cache(ctx: &egui::Context) -> std::sync::Arc<std::sync::Mutex<Cache>> {
    let key = egui::Id::unique("note-image-cache");
    type Shared = std::sync::Arc<std::sync::Mutex<Cache>>;
    ctx.data_mut(|d| d.get_temp_mut_or_insert_with(key, Shared::default).clone())
}

/// The picture as a texture, decoded when first asked for per `(entry, image)`; `None` (also kept) when the type is
/// not one reports embed or the bytes do not decode. Larger than the GPU takes: scaled down. It stays while frames
/// ask for it; see [`evict_unused`].
pub fn texture(ctx: &egui::Context, entry_id: i64, image: &NoteImage) -> Option<TextureHandle> {
    texture_at(ctx, entry_id, image, ctx.input(|i| i.time))
}

fn texture_at(ctx: &egui::Context, entry_id: i64, image: &NoteImage, now: f64) -> Option<TextureHandle> {
    let cache = cache(ctx);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    let slot = slot(&mut cache, entry_id, image, now);
    slot.texture.get_or_insert_with(|| decode(ctx, entry_id, image)).clone()
}

/// The size the picture is shown at in a texture, from its header alone: no pixels are decoded.
fn display_size(ctx: &egui::Context, entry_id: i64, image: &NoteImage, now: f64) -> Option<[usize; 2]> {
    let cache = cache(ctx);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    let max_side = ctx.input(|i| i.max_texture_side).max(1);
    *slot(&mut cache, entry_id, image, now).size.get_or_insert_with(|| {
        let reader = image::ImageReader::new(std::io::Cursor::new(&image.bytes))
            .with_guessed_format()
            .ok()?;
        let (width, height) = reader.into_dimensions().ok()?;
        (width > 0 && height > 0).then(|| fit([width as usize, height as usize], max_side))
    })
}

fn slot<'a>(cache: &'a mut Cache, entry_id: i64, image: &NoteImage, now: f64) -> &'a mut Slot {
    let slot = cache.entry((entry_id, image.id.clone())).or_insert(Slot {
        size: None,
        texture: None,
        last_used: now,
    });
    slot.last_used = now;
    slot
}

/// How many pictures are kept, for tests.
#[cfg(test)]
pub(super) fn cached_count(ctx: &egui::Context) -> usize {
    cache(ctx).lock().unwrap_or_else(|e| e.into_inner()).len()
}

/// Whether a picture of the entry was decoded, for tests.
#[cfg(test)]
pub(super) fn texture_cached(ctx: &egui::Context, entry_id: i64) -> bool {
    let cache = cache(ctx);
    let cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .iter()
        .any(|((entry, _), slot)| *entry == entry_id && slot.texture.is_some())
}

/// Once per frame: drops the pictures no frame has drawn for [`KEEP_SECONDS`] (a case that was left, a note that was
/// scrolled away or corrected), which frees their textures. Asks for a frame to come back to it while any are kept.
pub fn evict_unused(ctx: &egui::Context) {
    let keeping = evict_older_than(ctx, ctx.input(|i| i.time) - KEEP_SECONDS);
    if keeping {
        ctx.request_repaint_after(std::time::Duration::from_secs_f64(KEEP_SECONDS));
    }
}

/// Drops what was last used before `limit`; true while something is left.
fn evict_older_than(ctx: &egui::Context, limit: f64) -> bool {
    let cache = cache(ctx);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    cache.retain(|_, slot| slot.last_used >= limit);
    !cache.is_empty()
}

fn decode(ctx: &egui::Context, entry_id: i64, image: &NoteImage) -> Option<TextureHandle> {
    if !image.is_embeddable() {
        return None;
    }
    let mut pixels = image::load_from_memory(&image.bytes).ok()?.into_rgba8();
    let max_side = ctx.input(|i| i.max_texture_side).max(1);
    let [width, height] = fit([pixels.width() as usize, pixels.height() as usize], max_side);
    if (width as u32, height as u32) != pixels.dimensions() {
        pixels = image::imageops::resize(
            &pixels,
            width as u32,
            height as u32,
            image::imageops::FilterType::Triangle,
        );
    }
    let color = egui::ColorImage::from_rgba_unmultiplied([width, height], pixels.as_raw());
    Some(ctx.load_texture(
        format!("note-image-{entry_id}-{}", image.id),
        color,
        egui::TextureOptions::LINEAR,
    ))
}

/// The note's text exactly as signed, monospace and selectable.
pub fn source(ui: &mut egui::Ui, text: &str, size: f32, color: Color32) -> Response {
    ui.add(
        egui::Label::new(egui::RichText::new(text).font(FontId::monospace(size)).color(color))
            .selectable(true)
            .wrap(),
    )
}

/// Draws the note's Markdown; returns the id of the image that was clicked, if one was. The log uses
/// [`note_body_with`]; this is the same without the hook.
#[cfg_attr(not(test), allow(dead_code))]
pub fn note_body(
    ui: &mut egui::Ui,
    entry_id: i64,
    text: &str,
    images: &[NoteImage],
    size: f32,
    color: Color32,
) -> Option<String> {
    note_body_with(ui, entry_id, text, images, size, color, &mut |_| {})
}

/// [`note_body`], also handing every text and image widget it adds to `each` (for a context menu on the note).
pub fn note_body_with(
    ui: &mut egui::Ui,
    entry_id: i64,
    text: &str,
    images: &[NoteImage],
    size: f32,
    color: Color32,
    each: &mut dyn FnMut(&Response),
) -> Option<String> {
    let mut body = Body {
        entry_id,
        images,
        color,
        palette: *theme::current(ui.ctx()),
        each,
        clicked: None,
        nested: 0,
    };
    body.blocks(ui, &markup::parse(text), size);
    body.clicked
}

struct Body<'a> {
    entry_id: i64,
    images: &'a [NoteImage],
    color: Color32,
    palette: Palette,
    each: &'a mut dyn FnMut(&Response),
    clicked: Option<String>,
    /// counts the indented blocks, so that each has its own id
    nested: usize,
}

/// How the inline content around is drawn.
#[derive(Clone, Copy)]
struct Look {
    size: f32,
    bold: bool,
    italic: bool,
    link: bool,
}

impl Body<'_> {
    fn blocks(&mut self, ui: &mut egui::Ui, blocks: &[Block], size: f32) {
        for (i, block) in blocks.iter().enumerate() {
            if i > 0 {
                ui.add_space(size * 0.35);
            }
            self.block(ui, block, size);
        }
    }

    fn block(&mut self, ui: &mut egui::Ui, block: &Block, size: f32) {
        match block {
            Block::Paragraph(inlines) => self.inlines(
                ui,
                inlines,
                Look {
                    size,
                    bold: false,
                    italic: false,
                    link: false,
                },
            ),
            Block::Heading(level, inlines) => {
                let grow = match level {
                    1 => 6.0,
                    2 => 4.0,
                    3 => 2.0,
                    _ => 0.0,
                };
                self.inlines(
                    ui,
                    inlines,
                    Look {
                        size: size + grow,
                        bold: true,
                        italic: false,
                        link: false,
                    },
                );
            }
            Block::List { start, items } => {
                self.nested += 1;
                ui.indent(("note-list", self.nested), |ui| {
                    ui.visuals_mut().indent_has_left_vline = false;
                    for (i, item) in items.iter().enumerate() {
                        if i > 0 {
                            ui.add_space(size * 0.15);
                        }
                        ui.horizontal_top(|ui| {
                            let marker = match start {
                                Some(first) => format!("{}.", first + i as u64),
                                None => "•".to_string(),
                            };
                            ui.add(
                                egui::Label::new(egui::RichText::new(marker).size(size).color(self.color))
                                    .selectable(false),
                            );
                            ui.vertical(|ui| self.blocks(ui, item, size));
                        });
                    }
                });
            }
            Block::Quote(inner) => {
                self.nested += 1;
                let quote = ui.indent(("note-quote", self.nested), |ui| {
                    ui.visuals_mut().indent_has_left_vline = false;
                    self.blocks(ui, inner, size);
                });
                let rect = quote.response.rect;
                ui.painter()
                    .vline(rect.left() - 5.0, rect.y_range(), Stroke::new(2.0, self.palette.border));
            }
            Block::Code(code) => {
                Frame::new()
                    .fill(self.palette.panel)
                    .corner_radius(CornerRadius::same(2))
                    .inner_margin(Margin::symmetric(8, 6))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        let response = source(ui, code, size - 1.5, self.color);
                        (self.each)(&response);
                    });
            }
        }
    }

    /// One label per run of text; an image ends the run and stands on its own line.
    fn inlines(&mut self, ui: &mut egui::Ui, inlines: &[Inline], look: Look) {
        let mut job = LayoutJob::default();
        self.run(ui, inlines, look, &mut job);
        self.flush(ui, &mut job);
    }

    fn flush(&mut self, ui: &mut egui::Ui, job: &mut LayoutJob) {
        if job.is_empty() {
            return;
        }
        let response = ui.add(egui::Label::new(std::mem::take(job)).selectable(true).wrap());
        (self.each)(&response);
    }

    fn format(&self, look: Look) -> TextFormat {
        let family = if look.bold {
            theme::bold()
        } else if look.italic {
            theme::italic()
        } else {
            FontFamily::Proportional
        };
        TextFormat {
            font_id: FontId::new(look.size, family),
            color: if look.link { self.palette.accent } else { self.color },
            ..Default::default()
        }
    }

    fn muted(&self, look: Look) -> TextFormat {
        TextFormat {
            color: self.palette.muted,
            ..self.format(look)
        }
    }

    fn run(&mut self, ui: &mut egui::Ui, inlines: &[Inline], look: Look, job: &mut LayoutJob) {
        for inline in inlines {
            match inline {
                Inline::Text(text) => job.append(text, 0.0, self.format(look)),
                Inline::LineBreak => job.append("\n", 0.0, self.format(look)),
                Inline::Emphasis(inner) => self.run(ui, inner, Look { italic: true, ..look }, job),
                Inline::Strong(inner) => self.run(ui, inner, Look { bold: true, ..look }, job),
                Inline::Code(code) => job.append(
                    code,
                    0.0,
                    TextFormat {
                        font_id: FontId::monospace(look.size - 1.5),
                        background: self.palette.panel,
                        ..self.format(look)
                    },
                ),
                Inline::Link { text, url } => {
                    // never clickable: the address is text, so that it can be read and copied
                    self.run(ui, text, Look { link: true, ..look }, job);
                    if markup::shows_address(text, url) {
                        job.append(&format!(" ({url})"), 0.0, self.muted(look));
                    }
                }
                Inline::Image { alt, target } => match target {
                    ImageTarget::External(url) => {
                        job.append(&format!("[external image {url} not loaded]"), 0.0, self.muted(look));
                    }
                    ImageTarget::Note(id) => self.image(ui, id, alt, look, job),
                },
            }
        }
    }

    fn image(&mut self, ui: &mut egui::Ui, id: &str, alt: &str, look: Look, job: &mut LayoutJob) {
        let Some(image) = images::find(self.images, id).filter(|image| image.is_embeddable()) else {
            job.append(&format!("[image {id} missing]"), 0.0, self.muted(look));
            return;
        };
        let now = ui.input(|i| i.time);
        let Some(size) = display_size(ui.ctx(), self.entry_id, image, now) else {
            job.append(&format!("[image {id} could not be shown]"), 0.0, self.muted(look));
            return;
        };
        self.flush(ui, job);
        // the room is reserved from the header; the picture is decoded only once it is on screen
        let natural = egui::vec2(size[0] as f32, size[1] as f32);
        let scale = (ui.available_width() / natural.x)
            .min(MAX_IMAGE_HEIGHT / natural.y)
            .min(1.0);
        let (rect, _) = ui.allocate_exact_size(natural * scale, Sense::hover());
        if !ui.is_rect_visible(rect) {
            return;
        }
        let Some(texture) = texture_at(ui.ctx(), self.entry_id, image, now) else {
            let text = egui::RichText::new(format!("[image {id} could not be shown]")).color(self.palette.muted);
            ui.put(rect, egui::Label::new(text).wrap());
            return;
        };
        let alt = if alt.is_empty() { "Image" } else { alt };
        let response = ui
            .put(
                rect,
                egui::Image::new(egui::load::SizedTexture::new(texture.id(), natural))
                    .fit_to_exact_size(rect.size())
                    .alt_text(alt)
                    .sense(Sense::click()),
            )
            .on_hover_cursor(CursorIcon::PointingHand)
            .on_hover_text("Show full size");
        (self.each)(&response);
        if response.clicked() {
            self.clicked = Some(id.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(width: u32, height: u32) -> NoteImage {
        NoteImage::from_rgba(width, height, &vec![200u8; (width * height * 4) as usize]).unwrap()
    }

    #[test]
    fn fit_scales_to_the_texture_limit() {
        assert_eq!(fit([11520, 2160], 8192), [8192, 1536]);
        assert_eq!(fit([2160, 11520], 8192), [1536, 8192]);
        assert_eq!(fit([100, 50], 8192), [100, 50]);
        assert_eq!(fit([8192, 8192], 8192), [8192, 8192]);
        // never a zero side, which no texture can have
        assert_eq!(fit([100_000, 3], 8192), [8192, 1]);
    }

    #[test]
    fn note_body_draws_without_a_click_and_without_images() {
        let ctx = egui::Context::default();
        theme::install_fonts(&ctx); // the bold and italic families
        let mut clicked = Some(String::new());
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            clicked = note_body(
                ui,
                1,
                "# T\n\n- a\n- b\n\n> q\n\n```\ncode\n```",
                &[],
                16.0,
                Color32::BLACK,
            );
        });
        output.textures_delta.clear();
        assert_eq!(clicked, None);
    }

    #[test]
    fn a_screenshot_over_the_texture_limit_is_scaled_down() {
        let ctx = egui::Context::default();
        let limit = ctx.input(|i| i.max_texture_side);
        let image = png(limit as u32 + 500, 20);
        let texture = texture(&ctx, 1, &image).expect("decodes");
        assert_eq!(texture.size(), fit([limit + 500, 20], limit));
        assert_eq!(texture.size()[0], limit);
    }

    #[test]
    fn only_decodable_embeddable_images_get_a_texture() {
        let ctx = egui::Context::default();
        let mut broken = png(2, 2);
        broken.bytes = b"not a picture".to_vec();
        assert!(texture(&ctx, 1, &broken).is_none());
        let mut svg = png(2, 2);
        svg.mime = "image/svg+xml".into();
        assert!(texture(&ctx, 1, &svg).is_none());
        assert!(texture(&ctx, 2, &png(2, 2)).is_some());
    }

    #[test]
    fn the_size_comes_from_the_header_without_decoding() {
        let ctx = egui::Context::default();
        let image = png(30, 20);
        assert_eq!(display_size(&ctx, 1, &image, 0.0), Some([30, 20]));
        assert!(cache(&ctx).lock().unwrap()[&(1, image.id.clone())].texture.is_none());
        let mut broken = png(2, 2);
        broken.bytes = b"not a picture".to_vec();
        assert_eq!(display_size(&ctx, 2, &broken, 0.0), None);
    }

    #[test]
    fn pictures_not_drawn_for_30_seconds_are_dropped() {
        let ctx = egui::Context::default();
        let (old, fresh) = (png(2, 2), png(3, 3));
        let _ = texture_at(&ctx, 1, &old, 0.0).unwrap();
        let _ = texture_at(&ctx, 2, &fresh, 20.0).unwrap();
        assert_eq!(cached_count(&ctx), 2);
        // 35 s: the first is 35 s old, the second 15 s; drawing the first again would keep it
        assert!(evict_older_than(&ctx, 35.0 - KEEP_SECONDS));
        assert_eq!(cached_count(&ctx), 1);
        assert!(cache(&ctx).lock().unwrap().contains_key(&(2, fresh.id.clone())));
        let _ = texture_at(&ctx, 2, &fresh, 40.0).unwrap();
        assert!(!evict_older_than(&ctx, 71.0 - KEEP_SECONDS));
        assert_eq!(cached_count(&ctx), 0);
    }

    #[test]
    fn a_texture_is_decoded_once_per_entry_and_image() {
        let ctx = egui::Context::default();
        let image = png(3, 3);
        let first = texture(&ctx, 1, &image).unwrap();
        // the cache answers by key: the bytes are not looked at again
        let mut tampered = image.clone();
        tampered.bytes.clear();
        assert_eq!(texture(&ctx, 1, &tampered).unwrap().id(), first.id());
        assert!(texture(&ctx, 2, &tampered).is_none());
    }
}
