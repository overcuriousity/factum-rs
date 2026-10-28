# Markdown notes and inline images Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Notes render as safe Markdown in the log and in all reports, and can carry pasted or inserted images that
are stored in the signed payload and shown inline.

**Architecture:** `src/images.rs` owns the image payload (types, limits, ids, references). `src/markup.rs` parses
note text once with `pulldown-cmark` into a small block/inline tree; the GUI, HTML, Markdown and PDF renderers each
walk that tree. Note text and the leaf format stay as they are; images ride in `payload`, which the leaf hash
already covers.

**Tech Stack:** Rust 2024, egui/eframe 0.37, `pulldown-cmark` 0.13, `image` 0.25, `arboard` 3, rusqlite.

**Spec:** `docs/superpowers/specs/2026-10-28-markdown-notes-images-design.md`

## Global Constraints

- No change to `log_service::FORMAT`, `leaf_data`, the schema, `entry_signed_payload` or `export/verify.py`.
- Payload of a note with images: `{"images": {"<id>": {"mime", "sha256", "data", "name"?}}}`; `<id>` = first 12
  hex characters of the SHA-256; `data` = standard base64 with padding. Notes without images keep `payload: null`.
- Reference in the text: `![<alt>](factum-image:<id>)`.
- Accepted: `image/png`, `image/jpeg`, `image/gif`, `image/webp`, detected from the bytes. Max 20 MB
  (`20 * 1024 * 1024` bytes of the original).
- Files stored byte for byte; clipboard pixels encoded once as PNG. Never downscaled or recompressed when stored.
- Rendered: paragraph, heading 1–6, lists (nested), block quote, code block; text, emphasis, strong, inline code,
  line break, link, image. Raw HTML and anything else: literal source text.
- Soft line breaks render as line breaks (old plain-text notes keep their lines).
- Links render as `text (address)`, once when text equals address; never clickable, in the GUI or in exports.
- External image URLs are never loaded: `[external image <url> not loaded]`; unknown id: `[image <id> missing]`.
- Keep it simple: no tables, footnotes, task lists, image editing, deduplication across entries, CLI image input.
- Match the surrounding code's comment density and naming; `cargo fmt`, `cargo clippy --all-targets` clean.

## Review Focus

- A screenshot larger than the GPU's `max_texture_side` (e.g. 3 × 4K monitors): the log must show it scaled, not
  panic or show nothing → test in Task 7.
- A payload edited to garbage (`images` not an object, bad base64, missing fields): the log and every export must
  still render the note, with `[image <id> missing]`, and verification must report the change → tests in Tasks 1, 2.
- A note whose text contains `<script>` or `<img src=x onerror=…>`: HTML export must show it as text → test in
  Task 4.
- The same image referenced twice in one note, or in two notes: rendered every time, written once as a file in the
  Markdown export and the bundle → tests in Tasks 5, 6.
- Clipboard with both text and an image (copy from a browser): Ctrl+V pastes the text, as before → Task 8 step.

---

### Task 1: Image payload module

**Files:**
- Create: `src/images.rs`
- Modify: `src/lib.rs` (add `pub mod images;`), `Cargo.toml`
- Test: unit tests in `src/images.rs`

**Interfaces:**
- Produces:
  ```rust
  pub const MAX_IMAGE_BYTES: usize = 20 * 1024 * 1024;
  pub const SCHEME: &str = "factum-image:";
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct NoteImage { pub id: String, pub mime: String, pub sha256: String, pub name: Option<String>, pub bytes: Vec<u8> }
  impl NoteImage {
      pub fn from_bytes(bytes: Vec<u8>, name: Option<String>) -> Result<Self>;
      pub fn from_rgba(width: u32, height: u32, rgba: &[u8]) -> Result<Self>; // name None, PNG
      pub fn extension(&self) -> &'static str; // png, jpg, gif, webp
      pub fn file_name(&self) -> String;       // "<sha256>.<ext>"
      pub fn reference(&self, alt: &str) -> String; // "![alt](factum-image:<id>)", `[` `]` removed from alt
  }
  pub fn referenced_ids(text: &str) -> Vec<String>; // unique, in order of first appearance
  pub fn to_payload(images: &[NoteImage]) -> Option<serde_json::Value>; // None when empty
  pub fn from_payload(payload: &serde_json::Value) -> Vec<NoteImage>;   // skips malformed items
  pub fn find<'a>(images: &'a [NoteImage], id: &str) -> Option<&'a NoteImage>;
  ```

- [ ] **Step 1: Make `image` a non-optional dependency** with `default-features = false, features = ["png", "jpeg",
  "gif", "webp"]` (PDF export needs decoding without the GUI); remove `dep:image` from the `gui` feature. Add
  `pulldown-cmark = { version = "0.13", default-features = false }` now too (Task 3).

- [ ] **Step 2: Write the failing tests**

```rust
#[test] fn detects_types_from_bytes_not_names() // PNG bytes named "x.jpg" → mime "image/png", extension "png"
#[test] fn refuses_unknown_types()              // b"%PDF-1.7" → Err, message contains "PNG, JPEG, GIF or WebP"
#[test] fn refuses_images_over_20_mb()          // valid PNG header padded to MAX_IMAGE_BYTES + 1 → Err, contains "20 MB"
#[test] fn id_is_the_first_12_hex_of_sha256()   // id == sha256[..12], sha256.len() == 64
#[test] fn from_rgba_encodes_png_losslessly()   // 2×1 RGBA → decode with image crate → same pixels
#[test] fn referenced_ids_are_unique_and_ordered() // "![a](factum-image:aaaaaaaaaaaa) ![b](factum-image:bbbbbbbbbbbb) ![](factum-image:aaaaaaaaaaaa)" → [aaaa…, bbbb…]
#[test] fn payload_round_trips()                // from_payload(&to_payload(&[img]).unwrap()) == vec![img]
#[test] fn payload_layout_is_pinned()           // canonical_json(&to_payload(..)) == r#"{"images":{"<id>":{"data":"…","mime":"image/png","name":"a.png","sha256":"…"}}}"#; no "name" key when None
#[test] fn malformed_payload_items_are_skipped() // {"images": 5}, {"images": {"x": {"data": "!!"}}}, Value::Null → empty
```

- [ ] **Step 3: Run** `cargo test --lib images::` — expected: FAIL (module missing).

- [ ] **Step 4: Implement** `src/images.rs`. Type from `image::guess_format`, limited to the four formats.
  `from_payload` recomputes nothing: it takes `sha256`/`mime` as stored and decodes `data` with
  `base64::engine::general_purpose::STANDARD`; an item that does not decode is skipped. Error messages:
  `"Only PNG, JPEG, GIF or WebP images can be added."` and `"The image is larger than 20 MB."`.

- [ ] **Step 5: Run** `cargo test --lib images::` — expected: PASS. **Commit:** `Notes: image payload (types, limits, references)`.

### Task 2: Notes with images

**Files:**
- Modify: `src/notes.rs`
- Test: `tests/integrity.rs`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  ```rust
  impl Entry { pub fn images(&self) -> Vec<NoteImage>; } // from_payload(&self.payload())
  impl Factum<'_> {
      pub fn create_note_with_images(&self, note_text: &str, images: &[NoteImage], evidence_id: Option<i64>, case_id: i64) -> Result<i64>;
      pub fn correct_note_with_images(&self, note_id: i64, new_text: &str, images: &[NoteImage]) -> Result<i64>;
  }
  ```
  `create_note` / `correct_note` keep their signatures and call these with `&[]`.

- [ ] **Step 1: Write the failing tests** in `tests/integrity.rs`

```rust
#[test] fn note_images_are_stored_in_the_signed_payload()   // entry.images() == [img]; entry.text unchanged; verify_case OK
#[test] fn changing_one_base64_character_fails_verification() // UPDATE entries SET payload_json = <one char changed> → verify_case reports the leaf as FAIL
#[test] fn unreferenced_images_are_not_saved()               // two images given, text references one → entry.images().len() == 1
#[test] fn a_reference_without_its_image_is_refused()       // Err, message "The note refers to image <id>, which is not attached."; no entry written
#[test] fn a_correction_keeps_only_referenced_images()      // note with A and B; correct with text referencing B and new C → images == [B, C]
#[test] fn notes_without_images_keep_a_null_payload()        // payload_json IS NULL
#[test] fn garbage_payload_still_lists_the_note()            // payload_json = '{"images":5}' → entry.images() empty, list_entries still returns it
```

- [ ] **Step 2: Run** `cargo test --test integrity` — expected: the new tests FAIL.

- [ ] **Step 3: Implement.** Filter `images` to `referenced_ids(text)` (order of the references), error on a
  missing id, pass `Append { payload: images::to_payload(&kept), .. }`. Image ids/IoC: none extra needed — the
  12-hex id is not matched by the IoC hash pattern; add one assertion to `note_images_are_stored_in_the_signed_payload`
  that the entry has no hash IoC.

- [ ] **Step 4: Run** `cargo test` — expected: PASS. **Commit:** `Notes: images in the signed payload`.

### Task 3: Markup tree

**Files:**
- Create: `src/markup.rs`
- Modify: `src/lib.rs`
- Test: unit tests in `src/markup.rs`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum Block { Paragraph(Vec<Inline>), Heading(u8, Vec<Inline>), List { start: Option<u64>, items: Vec<Vec<Block>> }, Quote(Vec<Block>), Code(String) }
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum Inline { Text(String), Emphasis(Vec<Inline>), Strong(Vec<Inline>), Code(String), LineBreak, Link { text: Vec<Inline>, url: String }, Image { alt: String, target: ImageTarget } }
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum ImageTarget { Note(String), External(String) } // Note(id) for "factum-image:<id>"
  pub fn parse(text: &str) -> Vec<Block>;
  pub fn plain(inlines: &[Inline]) -> String;         // text content only, images as alt
  pub fn shows_address(text: &[Inline], url: &str) -> bool; // false when plain(text) == url
  pub fn to_plain(text: &str) -> String;              // whole note flattened, for one-line views
  ```

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn renders_the_supported_elements() // "# H\n\n*e* **s** `c`\n\n- a\n  - b\n\n> q\n\n```\nx\n```" → exact Block tree
#[test] fn soft_breaks_are_line_breaks()   // "a\nb" → [Paragraph([Text("a"), LineBreak, Text("b")])]
#[test] fn raw_html_is_text()               // "<b>x</b>" and "<!-- c -->" → their literal source as Text
#[test] fn rules_and_unsupported_blocks_keep_their_source() // "---" → Paragraph([Text("---")])
#[test] fn tags_are_not_headings()          // "#tag here" → Paragraph
#[test] fn note_and_external_images()       // factum-image:abc → ImageTarget::Note("abc"); https://x/y.png → External
#[test] fn shows_address_only_when_it_differs() // [https://a](https://a) → false; [a](https://a) → true
#[test] fn to_plain_flattens()              // "**a** ![s](factum-image:abc)" → "a s"
```

- [ ] **Step 2: Run** `cargo test --lib markup::` — expected: FAIL.

- [ ] **Step 3: Implement** with `Parser::new_ext(text, Options::empty()).into_offset_iter()` and a stack of open
  containers. `Event::Html`/`InlineHtml` → `Text` of the event's text; any `Start(tag)` not in the supported set →
  one `Text` of `&text[range]`, skipping events until its `End`. Adjacent `Text`s merged.

- [ ] **Step 4: Run** `cargo test --lib markup::` — expected: PASS. **Commit:** `Markup: one parsed tree for every renderer`.

### Task 4: HTML report

**Files:**
- Modify: `src/export/model.rs` (`ReportEntry.images: Vec<NoteImage>`, filled for notes from `entry.images()`),
  `src/export/html.rs`
- Test: `tests/export.rs`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `pub fn markup_html(text: &str, images: &[NoteImage]) -> String` in `src/export/html.rs`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn html_report_renders_markdown_and_embeds_images() // contains "<strong>", "data:image/png;base64,", "<details class='source'>" with the escaped source
#[test] fn html_report_shows_link_addresses()               // "[here](https://x.test)" → "here (https://x.test)", no "<a "
#[test] fn html_report_escapes_raw_html()                   // "<script>alert(1)</script>" and "<img src=x onerror=alert(1)>" → appear escaped, no "<script", no "onerror=" outside escaped text
#[test] fn html_report_marks_missing_images()               // reference without payload (set by SQL) → "[image <id> missing]"
```

- [ ] **Step 2: Run** `cargo test --test export html_report` — expected: FAIL.

- [ ] **Step 3: Implement.** `note_html` replaces `<pre class='text'>` with `<div class='text'>{markup_html}</div>`;
  when `!print_variant`, add `<details class='source'><summary>Source</summary><pre>{escaped text}</pre></details>`
  (pass `print_variant` into `note_html`). CSS: `.text img { max-width: 100%; height: auto; }`; `.text` keeps the
  serif note font. Every text node through `escape`. System entries are unchanged.

- [ ] **Step 4: Run** `cargo test` — expected: PASS. **Commit:** `Reports: HTML renders note Markdown and images`.

### Task 5: Markdown report and bundle

**Files:**
- Modify: `src/export/markdown.rs`, `src/export/mod.rs`, `src/export/bundle.rs`
- Test: `tests/export.rs`

**Interfaces:**
- Consumes: Tasks 1–4 (`ReportEntry.images`).
- Produces:
  ```rust
  pub fn render_markdown(model: &ReportModel, image_dir: &str) -> String; // image links: "<image_dir>/<sha256>.<ext>"
  pub fn image_files(model: &ReportModel) -> Vec<(String, Vec<u8>)>;     // (file_name, bytes), unique by sha256, notes only
  pub fn build_bundle(&self, model: &ReportModel, reports: &[(&str, Vec<u8>)], images: &[(String, Vec<u8>)], out_path: &Path) -> Result<PathBuf>;
  ```

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn markdown_report_renders_through_the_tree() // "**b** <b>x</b> [l](https://x.test)" → contains "**b**", "\<b\>x\</b\>", "l (`https://x.test`)"
#[test] fn markdown_export_writes_image_files()        // export(["md"]) → "<stem>.md" and "<stem>_images/<sha>.png"; the .md references "<stem>_images/<sha>.png"; bytes equal the original
#[test] fn same_image_twice_is_written_once()          // two notes with the same image → one file, both referenced
#[test] fn bundle_carries_images_in_the_manifest()     // bundle has "images/<sha>.png", MANIFEST.sha256 lists it, report.md references "images/<sha>.png"; verify_py passes when python3 exists
```

- [ ] **Step 2: Run** `cargo test --test export markdown` — expected: FAIL.

- [ ] **Step 3: Implement.** Text nodes escape `` \ ` * _ [ ] < > # | `` and, at the start of a line, `+`, `-` and
  `<digits>.`/`<digits>)`; code via the existing `fence`; links as `text (`url`)` (inline code keeps them
  unclickable); quotes as `> `, lists indented by 2 per level. `export()` writes `<stem>_images/` only when there
  are images and pushes each written image path onto `written`; the bundle gets `render_markdown(&model, "images")`.
  Add to `BUNDLE_README` contents: `` - `images/` — images of notes, named by their SHA-256 (also in `case.json`) ``.

- [ ] **Step 4: Run** `cargo test` — expected: PASS. **Commit:** `Reports: Markdown renders notes, images next to the report and in the bundle`.

### Task 6: PDF report

**Files:**
- Modify: `src/export/pdf.rs`
- Test: unit tests in `src/export/pdf.rs`, `tests/export.rs`

**Interfaces:**
- Consumes: Tasks 1, 3, 4.
- Produces (private to `pdf.rs`): `struct Span { style: Style, text: String }`,
  `fn rich_paragraph(&mut self, spans: &[Span], indent: f32)`, `fn image(&mut self, image: &NoteImage, indent: f32)`,
  `fn markup(&mut self, text: &str, images: &[NoteImage], body: Style)`,
  `fn spans(inlines: &[Inline], body: Style) -> Vec<Span>` (free function; links become `text (url)` per
  `markup::shows_address`, line breaks become `"\n"` in the span text).

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn rich_paragraph_wraps_across_styles()    // bold + regular spans wider than CONTENT_WIDTH → two lines, no word split at a span border
#[test] fn pdf_embeds_note_images()                // tests/export.rs: export(["pdf"]) of a note with a 3×2 PNG → file bytes contain "/Subtype /Image", "/Width 3", "/Height 2"
#[test] fn pdf_writes_a_shared_image_once()        // tests/export.rs: same image in two notes → "/Subtype /Image" exactly once
#[test] fn truncated_images_do_not_decode()        // decode(&img with PNG magic, truncated) == None (the note then shows "[image <id> could not be shown]")
#[test] fn spans_carry_styles_and_link_addresses() // spans(&inlines of "**b** *i* `c` [l](https://x.test)", body) → fonts [Bold, Sans, Italic, Sans, Mono, Sans, Sans], last text "l (https://x.test)" (exact split may merge adjacent same-style spans; assert on the style of each word)
#[test] fn markup_draws_bold_runs()                // Writer::new(); markup("**b** a", &[], body) → current page string contains "/F1 " and "/F0 "
```

- [ ] **Step 2: Run** `cargo test pdf` and `cargo test --test export pdf` — expected: FAIL.

- [ ] **Step 3: Implement.**
  - `rich_paragraph`: wrap word by word across spans, a `"\n"` forces a break; line height = max of the spans'
    `line_height()`.
  - `fn decode(image: &NoteImage) -> Option<PdfImage>` (RGB8 + optional alpha), unit-tested above.
  - Headings Bold at body size + 4 (h1), +2 (h2), +1 (h3–6); code blocks via `paragraph_with_background` in Mono;
    list items indented 14 pt with `•` or `N.`; quotes indented 12 pt with a 1.5 pt `BORDER` bar.
  - Strong → Bold, Emphasis → Italic, inline code → Mono; nested strong in emphasis → Bold.
  - Images: decode with `image::load_from_memory`, store RGB8 + optional alpha once per sha256 in the `Writer`;
    `serialize` writes each as `/Type /XObject /Subtype /Image /ColorSpace /DeviceRGB /BitsPerComponent 8
    /Filter /FlateDecode` with an `/SMask` for alpha, and every page's `/Resources` gets the `/XObject` dict.
    Size: width = min(content width − indent, pixels × 0.75), height by aspect, capped at page content height;
    `ensure(height)` before drawing; draw `q w 0 0 h x y cm /ImN Do Q`.
  - Notes call `pdf.markup(&item.text, &item.images, body)` instead of `pdf.paragraph(body, &item.text, 0.0)`.
    The activity list and the appendix are unchanged.

- [ ] **Step 4: Run** `cargo test` — expected: PASS. Open one generated PDF in a viewer (or `pdftoppm` if
  installed) and look at it. **Commit:** `Reports: PDF renders note Markdown and images`.

### Task 7: Log rendering (GUI)

**Files:**
- Create: `src/gui/markup_view.rs`
- Modify: `src/gui/mod.rs` (module, image viewer window), `src/gui/widgets.rs` (`note_card`, compact card,
  `CardAction`)
- Test: `src/gui/tests.rs`, unit tests in `markup_view.rs`

**Interfaces:**
- Consumes: Tasks 1–3, `theme::bold()`, `theme::italic()`, `theme::NOTE_SIZE`.
- Produces:
  ```rust
  pub fn note_body(ui: &mut egui::Ui, text: &str, images: &[NoteImage], size: f32, color: Color32) -> Option<String>; // Some(sha256) when an image was clicked
  pub fn texture(ctx: &egui::Context, image: &NoteImage) -> Option<egui::TextureHandle>; // cached by sha256, None if undecodable
  pub fn fit(size: [usize; 2], max_side: usize) -> [usize; 2]; // keeps aspect ratio
  CardAction::OpenImage(i64 /*entry id*/, String /*sha256*/)
  ```

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn fit_scales_to_the_texture_limit()      // fit([11520, 2160], 8192) == [8192, 1536]; fit([100, 50], 8192) == [100, 50]
#[test] fn note_card_renders_markdown()           // kittest: note "**bold** text" → a label "bold" exists, no label containing "**"
#[test] fn source_toggle_shows_the_literal_text() // kittest: click "Show source" on the card → a label "**bold** text" exists
#[test] fn note_card_shows_its_image()            // kittest: note with a 4×4 PNG → an egui Image widget with size ≤ card width and ≤ 400 high
#[test] fn link_shows_its_address_and_is_not_clickable() // kittest: "[l](https://x.test)" → text "l (https://x.test)", no hyperlink widget
```

- [ ] **Step 2: Run** `cargo test --lib gui::` — expected: FAIL.

- [ ] **Step 3: Implement.**
  - Inline runs as one `LayoutJob` per paragraph/heading (`TextFormat` with `theme::bold()`/`theme::italic()`/
    monospace), selectable `Label`; headings at `size + 6/4/2`; lists and quotes via `ui.indent`; code blocks in a
    `Frame` with code background.
  - Images: decode once (`image::load_from_memory`), downscale with `fit(.., ctx.input(|i| i.max_texture_side))`,
    `ctx.load_texture`, cache in `ctx.data_mut` temp storage keyed by sha256 (also caching `None`). Displayed at most
    card width × 400 px, `Sense::click()` → return the sha256. Undecodable → muted text `[image <id> could not be shown]`.
  - Source toggle: a small icon button in the card's action row, hover text `Show source` / `Show formatted`,
    state in `ui.data_mut` keyed by `("source", entry.id)`; source view = monospace selectable label of
    `entry.text`.
  - The compact pinned-panel card shows `markup::to_plain(&entry.text)`.
  - `CardAction::OpenImage` opens an `egui::Window` titled `Image <id>` showing the texture at its (fitted) size in
    a `ScrollArea`; one viewer at a time, closable.

- [ ] **Step 4: Run** `cargo test` — expected: PASS, existing kittest snapshots updated only where note text is
  rendered differently (review each snapshot diff). **Commit:** `Log: notes render as Markdown with images and a source toggle`.

### Task 8: Composer and correction dialog

**Files:**
- Create: `src/gui/note_editor.rs`
- Modify: `src/gui/mod.rs` (composer state, `submit_note`, paste/drop handling), `src/gui/dialogs.rs`
  (`Dialog::Correct`, `DialogResult::Correct`), `Cargo.toml` (`arboard = { version = "3", optional = true }` added to
  the `gui` feature), `CHANGELOG.md`, `README.md` (one line on Markdown and images in the notes section)
- Test: unit tests in `note_editor.rs`, `src/gui/tests.rs`

**Interfaces:**
- Consumes: Tasks 1, 2, 7.
- Produces:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum Format { Bold, Italic, Code, Link, Heading, List, Quote }
  pub fn apply(text: &str, selection: std::ops::Range<usize>, format: Format) -> (String, std::ops::Range<usize>); // char indices
  pub fn insert(text: &mut String, at: usize, snippet: &str) -> usize; // new cursor (char index)
  pub fn remove_image(text: &mut String, images: &mut Vec<NoteImage>, id: &str); // drops the image and its references
  pub fn toolbar(ui: &mut egui::Ui, editor_id: egui::Id, text: &mut String, images: &mut Vec<NoteImage>) -> Result<()>;
  pub fn thumbnails(ui: &mut egui::Ui, text: &mut String, images: &mut Vec<NoteImage>);
  pub fn clipboard_image() -> Option<NoteImage>; // None when the clipboard has text or no image
  ```
  `Dialog::Correct { entry_id, original, text, images: Vec<NoteImage> }`,
  `DialogResult::Correct { entry_id, text, images: Vec<NoteImage> }`; App field `composer_images: Vec<NoteImage>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn apply_wraps_the_selection()       // ("a b", 2..3, Bold) → ("a **b**", 4..5); Italic "*", Code "`"
#[test] fn apply_inserts_a_placeholder()     // ("", 0..0, Bold) → ("**bold**", 2..6); Link on "x" → ("[x](url)", 4..7)
#[test] fn line_formats_prefix_every_line()  // ("a\nb", 0..3, List) → ("- a\n- b", ..); Quote "> "; Heading "## " on the cursor's line only
#[test] fn remove_image_drops_its_references() // text with the reference twice → both gone, image removed
#[test] fn composer_saves_a_pasted_image()   // kittest: push a NoteImage into composer_images + reference into composer, submit → entry.images().len() == 1, composer_images empty
#[test] fn correction_dialog_keeps_the_images() // kittest: correct a note with an image, change the text only → new version has the same image
```

- [ ] **Step 2: Run** `cargo test --lib gui::` — expected: FAIL.

- [ ] **Step 3: Implement.**
  - Toolbar above the composer (and above the correction editor): icon buttons with hover text `Bold`, `Italic`,
    `Code`, `Link`, `Heading`, `List`, `Quote`, `Image…`. Selection from `TextEdit::load_state(ctx, editor_id)`;
    after `apply`, store the new selection back and focus the editor.
  - `Image…`: `rfd::FileDialog` filtered to `png jpg jpeg gif webp`; `NoteImage::from_bytes(bytes, file name)`;
    insert `reference(<file stem>)` at the cursor. Dropped files (`ctx.input(|i| i.raw.dropped_files)`) the same way
    while the composer or the correction dialog is open.
  - Paste: when the editor has focus and Ctrl/Cmd+V is pressed, call `clipboard_image()`; it returns an image only
    when `arboard` has no text (so a browser copy with text and image pastes the text, as before); insert
    `reference("screenshot")`. Errors go through `self.run(..)`.
  - Thumbnails (64 px high) under the editor, each with a remove button (`remove_image`).
  - `submit_note` → `create_note_with_images(&text, &self.composer_images, ..)`; clear both on success. Correction
    starts with `entry.images()` and calls `correct_note_with_images`.
  - CHANGELOG `[Unreleased]` → `### Added`: Markdown in notes (toolbar, rendered in log and reports, source toggle);
    pasted and inserted images, signed in the note's payload, shown inline and exported.

- [ ] **Step 4: Run** `cargo test`, `cargo clippy --all-targets`, `cargo build --no-default-features` — expected:
  all clean. Manually on X11 (and Wayland if available): paste a screenshot, paste text with an image on the
  clipboard, drop a JPEG, insert via the button; note whether Wayland paste works and record the result in the PR.
  **Commit:** `Composer: Markdown toolbar, pasted and inserted images`.
