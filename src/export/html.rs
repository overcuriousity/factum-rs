//! Self-contained HTML report: the notes first, the verification data at the end.

use super::model::{ReportEntry, ReportModel, grouped_findings, readable_utc, status_sentence, verification_summary};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::images::{self, NoteImage};
use crate::markup::{self, Block, ImageTarget, Inline};
use crate::pystr::html_escape as escape;
use crate::verifier::Level;

/// inline only, no JavaScript: the report must open offline in any browser
pub const CSS: &str = "
body { font-family: Georgia, 'Times New Roman', serif; color: #292524; max-width: 46em; margin: 2em auto; padding: 0 1em;
       line-height: 1.45; }
h1 { font-size: 1.7em; margin-bottom: .1em; }
h2 { font-size: 1.25em; border-bottom: 1px solid #d6d3d1; padding-bottom: .2em; margin-top: 2em; }
h3 { font-size: 1em; }
.subtitle { color: #57534e; margin: 0 0 1em 0; }
table.meta td { padding: .1em 1.2em .1em 0; vertical-align: top; color: #57534e; }
table.grid { border-collapse: collapse; }
table.grid th, table.grid td { border: 1px solid #d6d3d1; padding: .25em .5em; text-align: left; vertical-align: top; }
.status { padding: .45em .8em; border: 1px solid; margin: 1em 0; font-size: .9em; }
.status-OK { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
.status-WARN { background: #fffbeb; border-color: #fde68a; color: #92400e; }
.status-FAIL { background: #fee2e2; border-color: #fca5a5; color: #b91c1c; font-weight: bold; }
.note { margin: 1.4em 0; padding-bottom: .8em; border-bottom: 1px solid #e7e5e4; }
.note-head { font-size: .85em; color: #78716c; margin-bottom: .3em; }
.note-head b { color: #44403c; }
.text { font-family: Georgia, 'Times New Roman', serif; font-size: 1.1em; margin: .2em 0 .4em 0; }
.text > :first-child { margin-top: 0; }
.text p { margin: .4em 0; }
.text img { max-width: 100%; height: auto; }
.text blockquote { margin: .4em 0 .4em 1em; padding-left: .8em; border-left: 3px solid #d6d3d1; color: #44403c; }
.text pre, .text code { font-family: 'Courier New', monospace; font-size: .9em; }
.text pre { white-space: pre-wrap; background: #f5f5f4; padding: .5em; }
.aside { font-size: .8em; font-style: italic; color: #78716c; }
.alert { font-size: .9em; font-weight: bold; color: #b91c1c; }
ul.activity { font-size: .9em; color: #57534e; padding-left: 1.2em; }
/* the technical part starts on its own page when printed, so the notes read without it */
.technical { page-break-before: always; margin-top: 3em; border-top: 2px solid #d6d3d1; font-size: .9em; color: #44403c; }
.mono { font-family: 'Courier New', monospace; font-size: .85em; word-break: break-all; }
.appendix pre, details pre { font-size: .75em; white-space: pre-wrap; word-break: break-all; background: #f5f5f4;
                              padding: .5em; }
";

pub const ALERT: &str = "⚠ This note failed the integrity check — see Verification.";

fn row(label: &str, value: &str) -> String {
    format!("<tr><td><b>{}</b></td><td>{}</td></tr>", escape(label), escape(value))
}

fn image_html(alt: &str, target: &ImageTarget, images: &[NoteImage]) -> String {
    match target {
        ImageTarget::External(url) => format!("[external image {} not loaded]", escape(url)),
        ImageTarget::Note(id) => match images::find(images, id).filter(|image| image.is_embeddable()) {
            Some(image) => format!(
                "<img src='data:{};base64,{}' alt='{}'>",
                escape(&image.mime),
                STANDARD.encode(&image.bytes),
                escape(alt)
            ),
            None => format!("[image {} missing]", escape(id)),
        },
    }
}

fn inlines_html(inlines: &[Inline], images: &[NoteImage]) -> String {
    let mut out = String::new();
    for inline in inlines {
        match inline {
            Inline::Text(text) => out += &escape(text),
            Inline::Emphasis(inner) => out += &format!("<em>{}</em>", inlines_html(inner, images)),
            Inline::Strong(inner) => out += &format!("<strong>{}</strong>", inlines_html(inner, images)),
            Inline::Code(code) => out += &format!("<code>{}</code>", escape(code)),
            Inline::LineBreak => out += "<br>",
            // never clickable: the address is printed so a reader of the report can see where it points
            Inline::Link { text, url } => {
                out += &inlines_html(text, images);
                if markup::shows_address(text, url) {
                    out += &format!(" ({})", escape(url));
                }
            }
            Inline::Image { alt, target } => out += &image_html(alt, target, images),
        }
    }
    out
}

fn blocks_html(blocks: &[Block], images: &[NoteImage]) -> String {
    let mut out = String::new();
    for block in blocks {
        match block {
            Block::Paragraph(inlines) => out += &format!("<p>{}</p>", inlines_html(inlines, images)),
            // the report's own headings are h1 to h3, so a note's start below them
            Block::Heading(level, inlines) => {
                let level = (*level + 2).min(6);
                out += &format!("<h{level}>{}</h{level}>", inlines_html(inlines, images));
            }
            Block::List { start, items } => {
                let (open, close) = match start {
                    None => ("<ul>".to_string(), "</ul>"),
                    Some(1) => ("<ol>".to_string(), "</ol>"),
                    Some(n) => (format!("<ol start='{n}'>"), "</ol>"),
                };
                out += &open;
                for item in items {
                    out += &format!("<li>{}</li>", blocks_html(item, images));
                }
                out += close;
            }
            Block::Quote(inner) => out += &format!("<blockquote>{}</blockquote>", blocks_html(inner, images)),
            Block::Code(code) => out += &format!("<pre>{}</pre>", escape(code)),
        }
    }
    out
}

/// A note's Markdown as HTML. Every text node is escaped, links are text with their address, and only the note's own
/// images are embedded.
pub fn markup_html(text: &str, images: &[NoteImage]) -> String {
    blocks_html(&markup::parse(text), images)
}

fn note_html(item: &ReportEntry, print_variant: bool) -> String {
    let mut head = format!("<b>{}</b>", escape(&readable_utc(Some(&item.origin_created_utc))));
    if let Some(evidence) = &item.evidence {
        head += &format!(" · {}", escape(evidence));
    }
    let mut parts = vec![
        format!("<div class='note'><div class='note-head'>{head}</div>"),
        format!("<div class='text'>{}</div>", markup_html(&item.text, &item.images)),
    ];
    if !print_variant {
        parts.push(format!(
            "<details class='source'><summary>Source</summary><pre>{}</pre></details>",
            escape(&item.text)
        ));
    }
    if item.status == Level::Fail {
        parts.push(format!("<div class='alert'>{ALERT}</div>"));
    }
    let mut asides = Vec::new();
    if let Some(note) = item.correction_note() {
        asides.push(escape(&note));
    }
    if !item.labels.is_empty() {
        asides.push(format!("Labels (not signed): {}", escape(&item.labels.join(", "))));
    }
    asides.push(format!("Note #{}", item.origin_id));
    parts.push(format!("<div class='aside'>{}</div></div>", asides.join(" · ")));
    parts.concat()
}

fn appendix_html(item: &ReportEntry, print_variant: bool) -> String {
    let body = escape(&item.integrity_lines().join("\n"));
    if print_variant {
        return format!(
            "<h3>#{} (leaf {})</h3><pre>{body}</pre>",
            item.entry_id, item.leaf_index
        );
    }
    format!(
        "<details><summary class='mono'>{}</summary><pre>{body}</pre></details>",
        escape(&item.short_line())
    )
}

/// The evidence table cells: id, name (with the description after a dash), hash, added, deleted.
pub fn evidence_cells(item: &super::model::EvidenceRow) -> [String; 5] {
    [
        item.id.to_string(),
        if item.details.is_empty() {
            item.description.clone()
        } else {
            format!("{} — {}", item.description, item.details)
        },
        if item.evidence_hash.is_empty() {
            "—".into()
        } else {
            item.evidence_hash.clone()
        },
        readable_utc(Some(&item.created_utc)),
        if item.deleted_utc.as_deref().is_some_and(|d| !d.is_empty()) {
            readable_utc(item.deleted_utc.as_deref())
        } else {
            "—".into()
        },
    ]
}

/// The meta rows at the top: (label, value).
pub fn meta_rows(model: &ReportModel) -> Vec<(&'static str, String)> {
    let case = &model.case;
    let mut meta = vec![("Case file", case.case_file.clone())];
    if !case.description.is_empty() {
        meta.push(("Description", case.description.clone()));
    }
    meta.push(("Opened", readable_utc(Some(&case.created_utc))));
    if case.archived_utc.as_deref().is_some_and(|a| !a.is_empty()) {
        meta.push(("Archived", readable_utc(case.archived_utc.as_deref())));
    }
    meta.push(("Exported", readable_utc(Some(&model.exported_utc))));
    meta
}

/// The technical rows of the verification section: (label, value).
pub fn technical_rows(model: &ReportModel) -> Vec<(&'static str, String)> {
    let seal = &model.seal;
    let unsigned = if seal.signature.as_deref().is_some_and(|s| !s.is_empty()) {
        ""
    } else {
        " (unsigned)"
    };
    let mut rows = vec![
        (
            "Exported with key",
            model.exporting_key.clone().unwrap_or_else(|| "none (unsigned)".into()),
        ),
        (
            "Export seal",
            format!("{} entries, root {}{unsigned}", seal.tree_size, seal.root_hash),
        ),
    ];
    for (fingerprint, username) in &model.report.signers {
        rows.push((
            "Signer",
            format!(
                "{} — {fingerprint}",
                username.as_deref().filter(|u| !u.is_empty()).unwrap_or("unknown")
            ),
        ));
    }
    rows
}

/// The print variant (used for PDF in factum-notes) expands the integrity appendix instead of using <details>.
pub fn render_html(model: &ReportModel, print_variant: bool) -> String {
    let (case, report) = (&model.case, &model.report);
    let overall = report.overall();
    let notes = model.notes();
    let mut parts = vec![
        "<!DOCTYPE html><html><head><meta charset='utf-8'>".to_string(),
        format!(
            "<title>{}</title><style>{CSS}</style></head><body>",
            escape(&format!("Case report {}", case.case_file))
        ),
        format!("<h1>{}</h1>", escape(&case.case_name)),
        "<table class='meta'>".into(),
    ];
    parts.extend(meta_rows(model).iter().map(|(label, value)| row(label, value)));
    parts.push("</table>".into());
    parts.push(format!(
        "<div class='status status-{overall}'><b>{overall}</b> — {}</div>",
        escape(&status_sentence(report))
    ));
    parts.push(format!("<h2>Notes ({})</h2>", notes.len()));
    if notes.is_empty() {
        parts.push("<p>No notes.</p>".into());
    }
    parts.extend(notes.iter().map(|item| note_html(item, print_variant)));
    parts.push("<h2>Evidence</h2>".into());
    if model.evidence.is_empty() {
        parts.push("<p>No evidence items.</p>".into());
    } else {
        parts.push(
            "<table class='grid'><tr><th>#</th><th>Description</th><th>Hash</th><th>Added</th><th>Deleted</th></tr>"
                .into(),
        );
        for item in &model.evidence {
            let cells: String = evidence_cells(item)
                .iter()
                .map(|cell| format!("<td>{}</td>", escape(cell)))
                .collect();
            parts.push(format!("<tr>{cells}</tr>"));
        }
        parts.push("</table>".into());
    }
    if !model.containers.is_empty() {
        parts.push("<h2>Containers</h2>".into());
        for container in &model.containers {
            parts.push(format!(
                "<h3>#{} {}</h3><table class='meta'>",
                container.id,
                escape(&container.name)
            ));
            parts.extend(container.rows().iter().map(|(label, value)| row(label, value)));
            parts.push("</table>".into());
            if container.files.is_empty() {
                parts.push("<p>No files.</p>".into());
                continue;
            }
            parts.push("<table class='grid'><tr><th>Path</th><th>Size</th><th>SHA-256</th></tr>".into());
            for cells in container.file_cells() {
                let cells: String = cells.iter().map(|cell| format!("<td>{}</td>", escape(cell))).collect();
                parts.push(format!("<tr>{cells}</tr>"));
            }
            parts.push("</table>".into());
        }
    }
    parts.push("<h2>Case activity</h2><ul class='activity'>".into());
    for item in model.activity() {
        let flag = if item.status == Level::Fail {
            " <span class='alert'>⚠ FAIL</span>"
        } else {
            ""
        };
        parts.push(format!(
            "<li>{} — {}{flag}</li>",
            escape(&readable_utc(Some(&item.origin_created_utc))),
            escape(&item.text)
        ));
    }
    parts.push("</ul>".into());

    parts.push("<div class='technical'>".into());
    parts.push(format!("<h2>Verification: {overall}</h2>"));
    parts.push(format!("<p class='mono'>{}</p>", escape(&verification_summary(report))));
    let findings = grouped_findings(report);
    if !findings.is_empty() {
        let items: String = findings
            .iter()
            .map(|(level, message)| format!("<li><b>{level}</b> {}</li>", escape(message)))
            .collect();
        parts.push(format!("<ul>{items}</ul>"));
    }
    parts.push("<table class='meta mono'>".into());
    parts.extend(technical_rows(model).iter().map(|(label, value)| row(label, value)));
    parts.push("</table>".into());
    parts.push("<h2>Integrity appendix</h2>".into());
    parts.push("<p>Every log entry in log order, including superseded versions of corrected notes.</p>".into());
    parts.push("<div class='appendix'>".into());
    parts.extend(model.appendix.iter().map(|item| appendix_html(item, print_variant)));
    parts.push("</div></div></body></html>".into());
    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_note_nested_100_000_deep_renders() {
        for note in markup::deeply_nested_notes() {
            assert!(markup_html(&note, &[]).contains('x'));
        }
    }
}
