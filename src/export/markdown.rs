//! Markdown report: notes rendered from the shared markup tree, a short integrity line per entry and an integrity
//! appendix. Whatever a note says is shown as text: HTML stays literal, links are never clickable.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use super::html::{evidence_cells, technical_rows};
use super::model::{ReportModel, grouped_findings, readable_utc, status_sentence, verification_summary};
use crate::images::{self, NoteImage};
use crate::markup::{self, Block, ImageTarget, Inline};
use crate::verifier::Level;

static SPECIAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([\\`*_\[\]<>#|&])").unwrap());
static BACKTICKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"`+").unwrap());

/// a code fence longer than any backtick run in the text, so note text is always shown literally
pub fn fence(text: &str) -> String {
    let longest = BACKTICKS
        .find_iter(text)
        .map(|run| run.as_str().len())
        .max()
        .unwrap_or(0);
    "`".repeat(3.max(longest + 1))
}

pub fn inline(text: &str) -> String {
    let flat = text.replace(['\r', '\n'], " ");
    // "&" too: otherwise an entity like "&amp;" in a name would render as "&"
    SPECIAL.replace_all(&flat, r"\$1").into_owned()
}

/// Inline code that keeps backticks and edge spaces of its content.
fn code_span(code: &str) -> String {
    let flat = code.replace(['\r', '\n'], " ");
    let longest = BACKTICKS
        .find_iter(&flat)
        .map(|run| run.as_str().len())
        .max()
        .unwrap_or(0);
    let delimiter = "`".repeat(longest + 1);
    if flat.is_empty() || flat.starts_with(['`', ' ']) || flat.ends_with(['`', ' ']) {
        format!("{delimiter} {flat} {delimiter}")
    } else {
        format!("{delimiter}{flat}{delimiter}")
    }
}

/// A file path as a link destination: characters that end or change a destination are percent-encoded.
fn destination(path: &str) -> String {
    let mut out = String::new();
    for c in path.chars() {
        if c.is_control() || matches!(c, ' ' | '(' | ')' | '<' | '>' | '%' | '\\') {
            let mut buffer = [0; 4];
            for byte in c.encode_utf8(&mut buffer).bytes() {
                out += &format!("%{byte:02X}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn image_markdown(alt: &str, target: &ImageTarget, images: &[NoteImage], image_dir: &str) -> String {
    match target {
        ImageTarget::External(url) => format!("[external image {} not loaded]", inline(url)),
        ImageTarget::Note(id) => match images::find(images, id).filter(|image| image.is_embeddable()) {
            Some(image) => format!(
                "![{}]({})",
                inline(alt),
                destination(&format!("{image_dir}/{}", image.file_name()))
            ),
            None => format!("[image {} missing]", inline(id)),
        },
    }
}

fn inlines_markdown(inlines: &[Inline], images: &[NoteImage], image_dir: &str) -> String {
    let mut out = String::new();
    for node in inlines {
        match node {
            Inline::Text(text) => out += &inline(text),
            Inline::Emphasis(inner) => out += &format!("*{}*", inlines_markdown(inner, images, image_dir)),
            Inline::Strong(inner) => out += &format!("**{}**", inlines_markdown(inner, images, image_dir)),
            Inline::Code(code) => out += &code_span(code),
            // a backslash at the end of a line is a hard break
            Inline::LineBreak => out += "\\\n",
            // never clickable: the address is inline code, so no viewer turns it into a link
            Inline::Link { text, url } => {
                out += &inlines_markdown(text, images, image_dir);
                if markup::shows_address(text, url) {
                    out += &format!(" ({})", code_span(url));
                }
            }
            Inline::Image { alt, target } => out += &image_markdown(alt, target, images, image_dir),
        }
    }
    out
}

/// A line that starts like a list item, rule or heading underline would change the structure.
fn escape_line_start(line: &str) -> String {
    // literal lines (HTML blocks) keep their indentation: up to three spaces still let a list, rule or fence start,
    // four make a code block. Non-breaking spaces show the indentation and start nothing.
    let stripped = line.trim_start_matches([' ', '\t']);
    if stripped.len() < line.len() {
        let indent = line[..line.len() - stripped.len()].chars().count();
        return format!("{}{stripped}", "&nbsp;".repeat(indent));
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if line.starts_with(['-', '+', '=', '~']) {
        format!("\\{line}")
    } else if digits > 0 && line[digits..].starts_with(['.', ')']) {
        format!("{}\\{}", &line[..digits], &line[digits..])
    } else {
        line.to_string()
    }
}

fn paragraph_lines(inlines: &[Inline], images: &[NoteImage], image_dir: &str) -> Vec<String> {
    inlines_markdown(inlines, images, image_dir)
        .split('\n')
        .map(escape_line_start)
        .collect()
}

fn prefixed(lines: Vec<String>, first: &str, rest: &str) -> Vec<String> {
    lines
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            let prefix = if index == 0 { first } else { rest };
            format!("{prefix}{line}").trim_end().to_string()
        })
        .collect()
}

fn blocks_markdown(blocks: &[Block], images: &[NoteImage], image_dir: &str, in_item: bool) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let tight = in_item
            && matches!(
                (index.checked_sub(1).map(|i| &blocks[i]), block),
                (Some(Block::Paragraph(_)), Block::List { .. })
            );
        if index > 0 && !tight {
            lines.push(String::new());
        }
        match block {
            Block::Paragraph(inlines) => lines.extend(paragraph_lines(inlines, images, image_dir)),
            // the report's own headings are h1 to h3, so a note's start below them
            Block::Heading(level, inlines) => {
                let text = inlines_markdown(inlines, images, image_dir).replace("\\\n", " ");
                lines.push(format!("{} {text}", "#".repeat(usize::from(*level + 3).min(6))));
            }
            Block::List { start, items } => {
                for (number, item) in items.iter().enumerate() {
                    let marker = match start {
                        None => "- ".to_string(),
                        Some(first) => format!("{}. ", first + number as u64),
                    };
                    let content = blocks_markdown(item, images, image_dir, true);
                    if content.is_empty() {
                        lines.push(marker.trim_end().to_string());
                    } else {
                        lines.extend(prefixed(content, &marker, &" ".repeat(marker.len())));
                    }
                }
            }
            Block::Quote(inner) => {
                let content = blocks_markdown(inner, images, image_dir, false);
                if content.is_empty() {
                    lines.push(">".to_string());
                } else {
                    lines.extend(prefixed(content, "> ", "> "));
                }
            }
            Block::Code(code) => {
                let marks = fence(code);
                lines.push(marks.clone());
                if !code.is_empty() {
                    lines.extend(code.split('\n').map(str::to_string));
                }
                lines.push(marks);
            }
        }
    }
    lines
}

/// A note's Markdown, rendered from the shared tree; images of the note link to `<image_dir>/<sha256>.<ext>`.
fn markup_markdown(text: &str, images: &[NoteImage], image_dir: &str) -> Vec<String> {
    blocks_markdown(&markup::parse(text), images, image_dir, false)
}

/// The images the report links to, as `(file name, bytes)`: those of the notes shown, each file once. The name is
/// computed from the bytes, so nothing a stored payload says can choose where a file is written.
pub fn image_files(model: &ReportModel) -> Vec<(String, Vec<u8>)> {
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for note in model.notes() {
        for image in note.images.iter().filter(|image| image.is_embeddable()) {
            let name = image.file_name();
            if seen.insert(name.clone()) {
                files.push((name, image.bytes.clone()));
            }
        }
    }
    files
}

pub fn render_markdown(model: &ReportModel, image_dir: &str) -> String {
    let (case, report) = (&model.case, &model.report);
    let overall = report.overall();
    let notes = model.notes();
    let mut lines = vec![
        format!("# {}", inline(&case.case_name)),
        String::new(),
        format!("**Case file:** {}  ", inline(&case.case_file)),
    ];
    if !case.description.is_empty() {
        lines.push(format!("**Description:** {}  ", inline(&case.description)));
    }
    let archived = match case.archived_utc.as_deref().filter(|a| !a.is_empty()) {
        Some(archived) => format!(" · **Archived:** {}", readable_utc(Some(archived))),
        None => String::new(),
    };
    lines.push(format!(
        "**Opened:** {}{archived}  ",
        readable_utc(Some(&case.created_utc))
    ));
    lines.push(format!("**Exported:** {}", readable_utc(Some(&model.exported_utc))));
    lines.push(String::new());
    lines.push(format!("> **{overall}** — {}", inline(&status_sentence(report))));
    lines.push(String::new());
    lines.push(format!("## Notes ({})", notes.len()));
    lines.push(String::new());
    if notes.is_empty() {
        lines.extend(["No notes.".to_string(), String::new()]);
    }
    for item in &notes {
        let evidence = item
            .evidence
            .as_ref()
            .map(|e| format!(" · {}", inline(e)))
            .unwrap_or_default();
        lines.push(format!(
            "### {}{evidence}",
            readable_utc(Some(&item.origin_created_utc))
        ));
        lines.push(String::new());
        lines.extend(markup_markdown(&item.text, &item.images, image_dir));
        lines.push(String::new());
        let mut details = Vec::new();
        if item.status == Level::Fail {
            details.push("**⚠ This note failed the integrity check — see Verification.**".to_string());
        }
        if let Some(note) = item.correction_note() {
            details.push(format!("_{}_", inline(&note)));
        }
        if !item.labels.is_empty() {
            details.push(format!("_Labels (not signed): {}_", inline(&item.labels.join(", "))));
        }
        details.push(format!("<sub>Note \\#{}</sub>", item.origin_id));
        lines.push(details.join("  \n"));
        lines.push(String::new());
    }
    lines.extend(["## Evidence".to_string(), String::new()]);
    if model.evidence.is_empty() {
        lines.push("No evidence items.".into());
    } else {
        lines.push("| # | Description | Hash | Added | Deleted |".into());
        lines.push("|---|---|---|---|---|".into());
        for item in &model.evidence {
            let cells: Vec<String> = evidence_cells(item).iter().map(|cell| inline(cell)).collect();
            lines.push(format!("| {} |", cells.join(" | ")));
        }
    }
    if !model.containers.is_empty() {
        lines.extend([String::new(), "## Containers".to_string()]);
        for container in &model.containers {
            lines.extend([
                String::new(),
                format!("### #{} {}", container.id, inline(&container.name)),
                String::new(),
            ]);
            lines.extend(
                container
                    .rows()
                    .iter()
                    .map(|(label, value)| format!("- **{label}:** {}", inline(value))),
            );
            lines.push(String::new());
            if container.files.is_empty() {
                lines.push("No files.".into());
                continue;
            }
            lines.push("| Path | Size | SHA-256 |".into());
            lines.push("|---|---|---|".into());
            for cells in container.file_cells() {
                let cells: Vec<String> = cells.iter().map(|cell| inline(cell)).collect();
                lines.push(format!("| {} |", cells.join(" | ")));
            }
        }
    }
    lines.extend([String::new(), "## Case activity".to_string(), String::new()]);
    for item in model.activity() {
        let flag = if item.status == Level::Fail {
            " **⚠ FAIL**"
        } else {
            ""
        };
        lines.push(format!(
            "- {} — {}{flag}",
            readable_utc(Some(&item.origin_created_utc)),
            inline(&item.text)
        ));
    }
    lines.extend([
        String::new(),
        "---".into(),
        String::new(),
        "## Verification".into(),
        String::new(),
        format!("**Result: {overall}**"),
        String::new(),
        inline(&verification_summary(report)),
        String::new(),
    ]);
    let findings: Vec<String> = grouped_findings(report)
        .iter()
        .map(|(level, message)| format!("- **{level}** {}", inline(message)))
        .collect();
    let has_findings = !findings.is_empty();
    lines.extend(findings);
    if has_findings {
        lines.push(String::new());
    }
    let technical = technical_rows(model);
    lines.push(format!("- **Exported with key:** {}", inline(&technical[0].1)));
    let seal = &model.seal;
    let unsigned = if seal.signature.as_deref().is_some_and(|s| !s.is_empty()) {
        ""
    } else {
        " (unsigned)"
    };
    lines.push(format!(
        "- **Export seal:** {} entries, root `{}`{unsigned}",
        seal.tree_size, seal.root_hash
    ));
    for (fingerprint, username) in &report.signers {
        lines.push(format!(
            "- **Signer:** {} `{fingerprint}`",
            inline(username.as_deref().filter(|u| !u.is_empty()).unwrap_or("unknown"))
        ));
    }
    lines.extend([
        String::new(),
        "## Integrity appendix".into(),
        String::new(),
        "Every log entry in log order, including superseded versions of corrected notes.".into(),
        String::new(),
    ]);
    for item in &model.appendix {
        let body = item.integrity_lines().join("\n");
        let body_fence = fence(&body);
        lines.extend([
            format!("### #{} (leaf {})", item.entry_id, item.leaf_index),
            String::new(),
            format!("`{}`", item.short_line()),
            String::new(),
            body_fence.clone(),
            body,
            body_fence,
            String::new(),
        ]);
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_note_nested_100_000_deep_renders() {
        for note in markup::deeply_nested_notes() {
            assert!(markup_markdown(&note, &[], "images").concat().contains('x'));
        }
    }

    #[test]
    fn inline_keeps_entities_literal() {
        assert_eq!(inline("R&D &amp; <b>"), "R\\&D \\&amp; \\<b\\>");
    }

    #[test]
    fn fence_is_longer_than_backtick_runs() {
        assert_eq!(fence("no ticks"), "```");
        assert_eq!(fence("a ```` b"), "`````");
    }
}
