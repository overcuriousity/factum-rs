# Markdown notes and inline images: design

Date: 2026-10-28. Status: approved in conversation, awaiting review of this written spec.

## 1. Intent

Notes are written in Markdown and shown rendered in the log and in the reports. Screenshots and image files can be
pasted or inserted into a note; they are stored in the note's signed payload and shown inline.

The signed text does not change: rendering is presentation only, and the exact source is always one click away.

## 2. Decisions taken in conversation

| Topic | Decision |
|---|---|
| Faithfulness | Safe rendering (fixed element set, raw HTML shown as text, link addresses always visible) plus a source toggle in the log. |
| Old notes | All notes render as Markdown, old ones included. No marker in the payload. |
| Image sources | Clipboard paste, file picker, drag and drop. |
| Image fidelity | Files stored byte for byte; pasted pixels encoded once as lossless PNG. Never downscaled or recompressed. |
| Size cap | 20 MB per image (original bytes). |
| Markdown export | Images as files next to the report, referenced by relative path. |
| PDF | Rendered Markdown only, no literal source per note. The integrity lines and appendix stay. |
| Renderer | One parser (`pulldown-cmark`), small own renderers per output. Kept simple. |

## 3. Storage

- The note text holds a reference: `![screenshot](factum-image:<id>)`, where `<id>` is the first 12 hex characters
  of the image's SHA-256. Not the full hash: the IoC pattern matches 32/40/64 hex characters and would record every
  image as a hash IoC.
- The bytes go in the entry's payload, which the leaf hash covers:

  ```json
  {"images": {"3f2a9c1b7d4e": {"mime": "image/png", "sha256": "<64 hex>", "data": "<base64>", "name": "shot.png"}}}
  ```

  `name` only for images inserted from a file. Standard base64 with padding.
- No change to the leaf format, `FORMAT`, the schema, the signed payload or `verify.py`. Notes without images keep
  `payload: null`.
- Accepted types: PNG, JPEG, GIF, WebP, detected from the bytes (magic numbers), not the file name. Larger than
  20 MB or another type: refused with a message, nothing inserted.
- `create_note` and `correct_note` take the images. The note is refused if its text references an id that is not
  among the images given. Images the text does not reference are dropped before saving.
- Corrections: the correction dialog starts with the old version's images; the new payload holds exactly the images
  the new text references. Each version is self-contained.

## 4. Rendering (`src/markup.rs`)

One module parses note text with `pulldown-cmark` (CommonMark, no extensions) into a small block/inline tree that
every output renders:

- Blocks: paragraph, heading (1–6), list (ordered/unordered, nested), block quote, code block.
- Inlines: text, emphasis, strong, inline code, soft/hard break, link, image.
- Raw HTML (block and inline) becomes literal text. Anything else unsupported falls back to its literal source.
- Links render as `text (address)`; when text and address are equal, only once. Never clickable (a log may hold
  malicious addresses); the address can be selected and copied.
- Images: `factum-image:<id>` resolves against the note's own payload. Unresolved, or any other URL: the text
  `[image <id> missing]` / `[external image <url> not loaded]`. Nothing is ever fetched.

## 5. GUI

- Composer toolbar: Bold, Italic, Code, Link, Heading, List, Quote, Image. Each wraps the selection or inserts at
  the cursor.
- Ctrl+V with an image on the clipboard (via `arboard`, already a dependency) inserts it as PNG at the cursor; text
  paste is unchanged. Dropped image files and the Image button read the file as is.
- Pending images show as thumbnails under the composer, each with a remove button, until the note is submitted or
  the composer is cleared.
- Note cards render the Markdown. A per-card toggle shows the exact source text (monospace, selectable).
- Images scale to the card width, at most about 400 px high; clicking opens a window at full size. Textures are
  cached by SHA-256.

## 6. Exports

- HTML: rendered Markdown, images as `data:` URIs (`max-width: 100%`), a collapsed `<details>` with the source per
  note.
- PDF: the layout engine gets bold, italic and mono runs, list and quote indents, and image XObjects (decoded with
  `image`, Flate-compressed RGB plus an SMask for alpha), scaled to the content width and at most a page high.
- Markdown export: rendered through the same tree, so the safety rules hold (raw HTML escaped, link addresses shown).
  Images are written to `<stem>_images/<sha256>.<ext>` and referenced relatively. `Factum::export` returns those
  files with the report.
- Bundle: the images under `images/`, listed in `MANIFEST.sha256`; `report.md` references them there. `case.json`
  carries the payload as before.

## 7. Side effects

- Tags, IoCs, search and the companion see the note text with references, never base64.
- Python factum-notes shows the reference as plain text; its `verify.py` verifies these entries unchanged.
- Wayland: `arboard` uses the data-control protocol, which some compositors (likely GNOME) do not offer; image paste
  may then not work. Inserting from a file always works. To be checked during implementation, not worked around.

## 8. Testing

- `markup`: each element; raw HTML literal; link address shown; missing and external images.
- Notes: image ids must resolve; unreferenced images dropped; type and size checks; correction carries only
  referenced images; changing one base64 character fails verification.
- Exports: HTML contains the `data:` URI and the source block; Markdown export writes the image files; bundle
  manifest lists them and `verify.py` passes; PDF contains an image XObject.
- GUI (egui_kittest): a toolbar button wraps the selection; the source toggle shows the literal text.

## 9. Out of scope

Tables, footnotes, task lists, image editing or annotation, image deduplication across entries, CLI image input.
