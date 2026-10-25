//! Markdown report: note text always literal, a short integrity line per entry and an integrity appendix.

use std::sync::LazyLock;

use regex::Regex;

use super::html::{evidence_cells, technical_rows};
use super::model::{ReportModel, grouped_findings, readable_utc, status_sentence, verification_summary};
use crate::verifier::Level;

/// a line starting like this would turn into a list, heading, rule or code block
static BLOCK_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([-+=~]|\d+[.)])").unwrap());
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

/// Note text as plain paragraphs: every character literal, line breaks kept, nothing read as Markdown.
pub fn prose(text: &str) -> Vec<String> {
    let normalised = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<String> = normalised
        .split('\n')
        .map(|raw| {
            let stripped = raw.trim_start_matches([' ', '\t']);
            let mut line = inline(stripped);
            if BLOCK_START.is_match(&line) {
                line = format!("\\{line}");
            }
            let indent = raw.chars().count() - stripped.chars().count();
            format!("{}{line}", "&nbsp;".repeat(indent))
        })
        .collect();
    // a trailing backslash is a hard line break; blank lines stay paragraph breaks
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let follows = index + 1 < lines.len() && !lines[index + 1].is_empty();
            if !line.is_empty() && follows {
                format!("{line}\\")
            } else {
                line.clone()
            }
        })
        .collect()
}

pub fn render_markdown(model: &ReportModel) -> String {
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
        lines.extend(prose(&item.text));
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
    fn prose_is_literal() {
        assert_eq!(
            prose("a\n\n- b\n1. c\n  d"),
            vec!["a", "", "\\- b\\", "\\1. c\\", "&nbsp;&nbsp;d"]
        );
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
