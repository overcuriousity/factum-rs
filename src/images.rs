//! Images embedded in a note. They live in the entry's signed payload, so the hash and signature cover the pixels too.
//! Notes refer to them as `![alt](factum-image:<id>)`.

use std::io::Cursor;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use image::{ImageFormat, RgbaImage};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::error::{FactumError, Result};
use crate::markup::{self, Block, ImageTarget, Inline};

pub const MAX_IMAGE_BYTES: usize = 20 * 1024 * 1024;
/// URL scheme of an image reference inside note text
pub const SCHEME: &str = "factum-image:";
/// The only types a report embeds or writes out; a stored `mime` is untrusted data.
pub const MIME_TYPES: [&str; 4] = ["image/png", "image/jpeg", "image/gif", "image/webp"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteImage {
    /// first 12 hex characters of the SHA-256
    pub id: String,
    pub mime: String,
    pub sha256: String,
    pub name: Option<String>,
    pub bytes: Vec<u8>,
}

impl NoteImage {
    /// The type comes from the bytes, never from `name`.
    pub fn from_bytes(bytes: Vec<u8>, name: Option<String>) -> Result<Self> {
        if bytes.len() > MAX_IMAGE_BYTES {
            return Err(FactumError::general("The image is larger than 20 MB."));
        }
        let mime = match image::guess_format(&bytes) {
            Ok(ImageFormat::Png) => "image/png",
            Ok(ImageFormat::Jpeg) => "image/jpeg",
            Ok(ImageFormat::Gif) => "image/gif",
            Ok(ImageFormat::WebP) => "image/webp",
            _ => {
                return Err(FactumError::general("Only PNG, JPEG, GIF or WebP images can be added."));
            }
        };
        let sha256 = hex::encode(Sha256::digest(&bytes));
        Ok(Self {
            id: sha256[..12].to_string(),
            mime: mime.to_string(),
            sha256,
            name,
            bytes,
        })
    }

    /// Encodes raw RGBA pixels (e.g. from the clipboard) as PNG.
    pub fn from_rgba(width: u32, height: u32, rgba: &[u8]) -> Result<Self> {
        let pixels = RgbaImage::from_raw(width, height, rgba.to_vec())
            .ok_or_else(|| FactumError::general("The image data is incomplete."))?;
        let mut bytes = Vec::new();
        pixels
            .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| FactumError::general(format!("The image could not be encoded: {e}")))?;
        Self::from_bytes(bytes, None)
    }

    pub fn extension(&self) -> &'static str {
        match self.mime.as_str() {
            "image/jpeg" => "jpg",
            "image/gif" => "gif",
            "image/webp" => "webp",
            _ => "png",
        }
    }

    /// Whether reports may show this image: its type is one of [`MIME_TYPES`].
    pub fn is_embeddable(&self) -> bool {
        MIME_TYPES.contains(&self.mime.as_str())
    }

    /// `<sha256>.<ext>`, the name used in exports. The hash is computed from the bytes: a stored payload is untrusted,
    /// and a tampered `sha256` such as `../../x` must never reach a file path.
    pub fn file_name(&self) -> String {
        format!("{}.{}", hex::encode(Sha256::digest(&self.bytes)), self.extension())
    }

    /// The Markdown that embeds this image; brackets would end the alt text early and are dropped.
    pub fn reference(&self, alt: &str) -> String {
        let alt: String = alt.chars().filter(|c| !matches!(c, '[' | ']')).collect();
        format!("![{alt}]({SCHEME}{})", self.id)
    }
}

/// Ids of the images a note text refers to, each once, in order of first appearance: exactly the
/// `factum-image:` images the rendered note shows ([`markup::parse`]), so nothing is saved that is not shown, and
/// nothing shown is left out.
pub fn referenced_ids(text: &str) -> Vec<String> {
    fn blocks(list: &[Block], ids: &mut Vec<String>) {
        for block in list {
            match block {
                Block::Paragraph(v) | Block::Heading(_, v) => inlines(v, ids),
                Block::List { items, .. } => items.iter().for_each(|item| blocks(item, ids)),
                Block::Quote(inner) => blocks(inner, ids),
                Block::Code(_) => {}
            }
        }
    }
    fn inlines(list: &[Inline], ids: &mut Vec<String>) {
        for inline in list {
            match inline {
                Inline::Emphasis(v) | Inline::Strong(v) | Inline::Link { text: v, .. } => inlines(v, ids),
                Inline::Image {
                    target: ImageTarget::Note(id),
                    ..
                } if !ids.contains(id) => ids.push(id.clone()),
                _ => {}
            }
        }
    }
    let mut ids = Vec::new();
    blocks(&markup::parse(text), &mut ids);
    ids
}

/// The `payload` of a note entry: `{"images": {<id>: {data, mime, name?, sha256}}}`, `None` without images.
pub fn to_payload(images: &[NoteImage]) -> Option<Value> {
    if images.is_empty() {
        return None;
    }
    let items: Map<String, Value> = images
        .iter()
        .map(|image| {
            let mut item = json!({
                "data": STANDARD.encode(&image.bytes),
                "mime": image.mime,
                "sha256": image.sha256,
            });
            if let Some(name) = &image.name {
                item["name"] = Value::String(name.clone());
            }
            (image.id.clone(), item)
        })
        .collect();
    Some(json!({ "images": items }))
}

/// Reads the images back from a payload as stored; items that are malformed are skipped.
pub fn from_payload(payload: &Value) -> Vec<NoteImage> {
    let Some(items) = payload.get("images").and_then(Value::as_object) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|(id, item)| {
            let text = |key: &str| item.get(key)?.as_str().map(str::to_string);
            Some(NoteImage {
                id: id.clone(),
                mime: text("mime")?,
                sha256: text("sha256")?,
                name: text("name"),
                bytes: STANDARD.decode(text("data")?).ok()?,
            })
        })
        .collect()
}

pub fn find<'a>(images: &'a [NoteImage], id: &str) -> Option<&'a NoteImage> {
    images.iter().find(|image| image.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_json;
    use serde_json::{Value, json};

    fn png(width: u32, height: u32) -> Vec<u8> {
        let rgba = vec![200u8; (width * height * 4) as usize];
        NoteImage::from_rgba(width, height, &rgba).unwrap().bytes
    }

    #[test]
    fn detects_types_from_bytes_not_names() {
        let image = NoteImage::from_bytes(png(1, 1), Some("x.jpg".into())).unwrap();
        assert_eq!(image.mime, "image/png");
        assert_eq!(image.extension(), "png");
        assert_eq!(image.name.as_deref(), Some("x.jpg"));
    }

    #[test]
    fn refuses_unknown_types() {
        let err = NoteImage::from_bytes(b"%PDF-1.7".to_vec(), None).unwrap_err();
        assert!(err.to_string().contains("PNG, JPEG, GIF or WebP"), "{err}");
    }

    #[test]
    fn refuses_images_over_20_mb() {
        let mut bytes = png(1, 1);
        bytes.resize(MAX_IMAGE_BYTES + 1, 0);
        let err = NoteImage::from_bytes(bytes, None).unwrap_err();
        assert!(err.to_string().contains("20 MB"), "{err}");
    }

    #[test]
    fn id_is_the_first_12_hex_of_sha256() {
        let image = NoteImage::from_bytes(png(2, 2), None).unwrap();
        assert_eq!(image.sha256.len(), 64);
        assert_eq!(image.id, image.sha256[..12]);
        assert_eq!(image.file_name(), format!("{}.png", image.sha256));
        assert_eq!(image.reference("a [b]"), format!("![a b](factum-image:{})", image.id));
    }

    #[test]
    fn file_name_ignores_a_tampered_stored_hash() {
        let mut image = NoteImage::from_bytes(png(2, 2), None).unwrap();
        let real = image.sha256.clone();
        image.sha256 = "../../x".into();
        assert_eq!(image.file_name(), format!("{real}.png"));
        assert!(image.is_embeddable());
        image.mime = "image/svg+xml".into();
        assert!(!image.is_embeddable());
    }

    #[test]
    fn from_rgba_encodes_png_losslessly() {
        let rgba = [255, 0, 0, 255, 0, 10, 20, 128];
        let image = NoteImage::from_rgba(2, 1, &rgba).unwrap();
        assert_eq!(image.mime, "image/png");
        assert_eq!(image.name, None);
        let decoded = image::load_from_memory(&image.bytes).unwrap().to_rgba8();
        assert_eq!(decoded.dimensions(), (2, 1));
        assert_eq!(decoded.as_raw().as_slice(), &rgba);
        assert!(NoteImage::from_rgba(2, 2, &rgba).is_err());
    }

    #[test]
    fn referenced_ids_are_unique_and_ordered() {
        let text = "![a](factum-image:aaaaaaaaaaaa) ![b](factum-image:bbbbbbbbbbbb) ![](factum-image:aaaaaaaaaaaa)";
        assert_eq!(referenced_ids(text), vec!["aaaaaaaaaaaa", "bbbbbbbbbbbb"]);
        assert!(referenced_ids("![x](https://example.org/a.png)").is_empty());
    }

    /// The cases where a pattern match and the Markdown parse disagree.
    fn reference_variants(id: &str) -> Vec<String> {
        vec![
            format!("![a [b] c](factum-image:{id})"),
            format!("![a](factum-image:{id} \"t\")"),
            format!("![a](<factum-image:{id}>)"),
            format!("![a][r]\n\n[r]: factum-image:{id}"),
            format!("![r]\n\n[r]: factum-image:{id}"),
        ]
    }

    #[test]
    fn referenced_ids_are_the_images_the_markdown_shows() {
        let id = "aaaaaaaaaaaa";
        for text in reference_variants(id) {
            assert_eq!(referenced_ids(&text), vec![id], "{text}");
        }
        // shown as text, not as an image: not referenced
        for text in [
            format!("`![a](factum-image:{id})`"),
            format!("```\n![a](factum-image:{id})\n```"),
            format!("\\![a](factum-image:{id})"),
            format!("[a](factum-image:{id})"),
        ] {
            assert!(referenced_ids(&text).is_empty(), "{text}");
        }
        // inside a link it is still an image
        assert_eq!(
            referenced_ids(&format!("[![a](factum-image:{id})](https://x)")),
            vec![id]
        );
    }

    #[test]
    fn payload_round_trips() {
        let image = NoteImage::from_bytes(png(3, 2), Some("a.png".into())).unwrap();
        let other = NoteImage::from_bytes(png(1, 2), None).unwrap();
        let images = vec![image, other];
        let payload = to_payload(&images).unwrap();
        let mut back = from_payload(&payload);
        back.sort_by(|a, b| a.id.cmp(&b.id));
        let mut expected = images.clone();
        expected.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(back, expected);
        assert!(find(&back, &images[0].id).is_some());
        assert!(find(&back, "000000000000").is_none());
    }

    #[test]
    fn payload_layout_is_pinned() {
        use base64::Engine as _;
        let image = NoteImage::from_bytes(png(1, 1), Some("a.png".into())).unwrap();
        let data = base64::engine::general_purpose::STANDARD.encode(&image.bytes);
        assert_eq!(
            canonical_json(&to_payload(std::slice::from_ref(&image)).unwrap()),
            format!(
                r#"{{"images":{{"{}":{{"data":"{}","mime":"image/png","name":"a.png","sha256":"{}"}}}}}}"#,
                image.id, data, image.sha256
            )
        );
        let nameless = NoteImage::from_bytes(png(1, 1), None).unwrap();
        let payload = to_payload(&[nameless]).unwrap();
        assert!(!canonical_json(&payload).contains("\"name\""));
        assert_eq!(to_payload(&[]), None);
    }

    #[test]
    fn malformed_payload_items_are_skipped() {
        assert!(from_payload(&json!({"images": 5})).is_empty());
        assert!(from_payload(&json!({"images": {"x": {"data": "!!"}}})).is_empty());
        assert!(from_payload(&Value::Null).is_empty());
    }
}
