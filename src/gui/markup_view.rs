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

/// The picture as a texture, decoded once per `(entry, image)` and kept for the session; `None` (also kept) when the
/// type is not one reports embed or the bytes do not decode. Larger than the GPU takes: shown scaled down.
pub fn texture(ctx: &egui::Context, entry_id: i64, image: &NoteImage) -> Option<TextureHandle> {
    let key = egui::Id::unique(("note-image", entry_id, &image.id));
    if let Some(cached) = ctx.data(|d| d.get_temp::<Option<TextureHandle>>(key)) {
        return cached;
    }
    let handle = decode(ctx, entry_id, image);
    ctx.data_mut(|d| d.insert_temp(key, handle.clone()));
    handle
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
        let Some(texture) = texture(ui.ctx(), self.entry_id, image) else {
            job.append(&format!("[image {id} could not be shown]"), 0.0, self.muted(look));
            return;
        };
        self.flush(ui, job);
        let natural = texture.size_vec2();
        let scale = (ui.available_width() / natural.x)
            .min(MAX_IMAGE_HEIGHT / natural.y)
            .min(1.0);
        let alt = if alt.is_empty() { "Image" } else { alt };
        let response = ui
            .add(
                egui::Image::new(egui::load::SizedTexture::new(texture.id(), natural))
                    .fit_to_exact_size(natural * scale)
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
