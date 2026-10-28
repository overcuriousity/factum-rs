//! Evidence containers in the GUI: their menu, the view of one container, opening its folder.

use std::path::Path;

use egui::{Align, Layout, RichText};

use super::dialogs::{VerifyAction, plural, report_window, verdict_color, verdict_mark};
use super::icons;
use super::theme::{self, MONO_SIZE, SMALL_SIZE};
use super::widgets::{self, IconButton};
use crate::container::FACTUM_NS;
use crate::container::verify::{ContainerFormat, ContainerReport};
use crate::container::volume::AddProgress;
use crate::containers::{ContainerDetail, ContainerSummary, human_size};
use crate::verifier::{Finding, Level};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerAction {
    AddFiles(i64),
    AddFolder(i64),
    Close(i64),
    /// close an open container whose file is missing (asks first)
    CloseWithoutFile(i64),
    Reopen(i64),
    Verify(i64),
    Locate(i64),
    ShowInFolder(i64),
    /// a log entry of the container, shown in the case log
    ShowEntry(i64),
}

/// The container's menu: (label, action, enabled). `busy`: files are being added to it right now.
pub fn menu_items(
    summary: &ContainerSummary,
    archived: bool,
    busy: bool,
) -> Vec<(&'static str, ContainerAction, bool)> {
    let id = summary.id;
    let writable = summary.open && !archived && !summary.missing && !busy;
    vec![
        ("Add Files…", ContainerAction::AddFiles(id), writable),
        ("Add Folder…", ContainerAction::AddFolder(id), writable),
        ("Close Container", ContainerAction::Close(id), writable),
        (
            "Close Without File…",
            ContainerAction::CloseWithoutFile(id),
            summary.open && !archived && summary.missing && !busy,
        ),
        (
            "Reopen Container",
            ContainerAction::Reopen(id),
            !summary.open && !archived && !busy,
        ),
        ("Verify Container…", ContainerAction::Verify(id), !summary.missing),
        ("Locate…", ContainerAction::Locate(id), summary.missing),
        ("Show in Folder", ContainerAction::ShowInFolder(id), !summary.missing),
    ]
}

/// The menu as the tree's context menu and the view's ⋯ button show it.
pub fn menu(
    ui: &mut egui::Ui,
    summary: &ContainerSummary,
    archived: bool,
    busy: bool,
    actions: &mut Vec<ContainerAction>,
) {
    for (index, (label, action, enabled)) in menu_items(summary, archived, busy).into_iter().enumerate() {
        if index == 4 || index == 5 {
            ui.separator();
        }
        if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
            actions.push(action);
        }
    }
}

/// The status bar while files are added: how far it got.
pub fn add_status(progress: &AddProgress, name: &str) -> String {
    let load = |value: &std::sync::atomic::AtomicU64| value.load(std::sync::atomic::Ordering::Relaxed);
    format!(
        "Adding to \"{name}\": {} / {} files · {} / {}",
        load(&progress.files),
        load(&progress.total_files),
        human_size(load(&progress.bytes)),
        human_size(load(&progress.total_bytes))
    )
}

/// The status bar while a close re-checks the container.
pub fn recheck_status(progress: &AddProgress, name: &str) -> String {
    add_status(progress, name).replacen("Adding to", "Re-checking", 1)
}

/// An xsd:dateTime as the view shows it: 2026-10-27 21:10:04 UTC.
pub fn short_time(xsd: &str) -> String {
    let seconds = xsd.trim_end_matches('Z').split('.').next().unwrap_or(xsd);
    format!("{} UTC", seconds.replace('T', " "))
}

/// A container's state in a word or three: open, closed · signed, closed · damaged, file missing.
pub fn state_text(summary: &ContainerSummary) -> &'static str {
    match summary {
        s if s.missing && s.open => "file missing",
        s if s.open => "open",
        s if s.damaged => "closed · damaged",
        s if s.signed => "closed · signed",
        _ => "closed · unsigned",
    }
}

/// The hover text of the container symbol on an evidence row.
pub fn symbol_hover(summaries: &[&ContainerSummary]) -> String {
    match summaries {
        [one] => format!("Container · {}", state_text(one)),
        many => {
            let open = many.iter().filter(|s| s.open).count();
            format!("{} containers · {open} open", many.len())
        }
    }
}

/// The hover text of a row of its own (a container without a live evidence item): its file, and why it has a row.
pub fn row_hover(summary: &ContainerSummary, evidence_deleted: bool) -> String {
    let file = match &summary.path {
        Some(path) if !summary.missing => path.display().to_string(),
        _ => "File missing — Locate…".to_string(),
    };
    match summary.evidence_id {
        Some(id) if evidence_deleted => format!("{file}\nEvidence #{id} (deleted)"),
        _ => file,
    }
}

/// Opens the file manager at the container (selected where the platform can do that); not waited for.
pub fn show_in_folder(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("explorer");
        command.arg(format!("/select,{}", path.display()));
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = std::process::Command::new("open");
        command.arg("-R").arg(path);
        command
    };
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let mut command = {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(path.parent().unwrap_or(path));
        command
    };
    let mut child = command.spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

fn small(text: impl Into<String>, color: egui::Color32) -> RichText {
    RichText::new(text.into()).size(SMALL_SIZE).color(color)
}

/// One line of the container's history: when, the entry (a link to it in the log), what happened.
fn history_row(ui: &mut egui::Ui, utc: &str, entry_id: i64, text: &str, actions: &mut Vec<ContainerAction>) {
    let p = *theme::current(ui.ctx());
    ui.horizontal(|ui| {
        ui.label(small(widgets::display_time(utc), p.muted).monospace());
        let link = egui::Button::new(small(format!("#{entry_id}"), p.accent)).frame_when_inactive(false);
        if ui.add(link).on_hover_text("Show in the log").clicked() {
            actions.push(ContainerAction::ShowEntry(entry_id));
        }
        ui.label(small(text, p.secondary));
    });
}

/// One container below its evidence's notes: what it is, what happened to it, its files.
pub fn container_section(
    ui: &mut egui::Ui,
    detail: &ContainerDetail,
    times: &std::collections::HashMap<String, String>,
    (archived, busy): (bool, bool),
    actions: &mut Vec<ContainerAction>,
) {
    let p = *theme::current(ui.ctx());
    let summary = &detail.summary;
    ui.add_space(16.0);
    ui.horizontal(|ui| {
        let color = if summary.open { p.accent } else { p.muted };
        ui.label(RichText::new(icons::CONTAINER).size(theme::ICON_SIZE).color(color));
        ui.label(RichText::new(&summary.name).family(theme::bold()).color(p.text));
        ui.label(small(
            format!("{} · {}", detail.file_name, state_text(summary)),
            p.muted,
        ));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            IconButton::new(icons::MORE, "Container actions").menu(ui, |ui| menu(ui, summary, archived, busy, actions));
        });
    });
    ui.separator();
    egui::Grid::new(("container-facts", summary.id))
        .num_columns(2)
        .spacing([12.0, 2.0])
        .show(ui, |ui| {
            ui.label(small("File", p.muted));
            match (&summary.path, summary.missing) {
                (Some(path), false) => {
                    ui.add(egui::Label::new(small(path.display().to_string(), p.secondary)).truncate());
                }
                _ => {
                    ui.horizontal(|ui| {
                        ui.label(small(format!("{} — missing", detail.file_name), p.warn));
                        if ui.small_button("Locate…").clicked() {
                            actions.push(ContainerAction::Locate(summary.id));
                        }
                    });
                }
            }
            ui.end_row();
            ui.label(small("UUID", p.muted));
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(&summary.uuid)
                        .size(SMALL_SIZE)
                        .monospace()
                        .color(p.secondary),
                );
                if IconButton::new(icons::COPY, "Copy").show(ui).clicked() {
                    ui.ctx().copy_text(summary.uuid.clone());
                }
            });
            ui.end_row();
            ui.label(small("Base path", p.muted));
            let base = if detail.base_path.is_empty() {
                "full paths"
            } else {
                detail.base_path.as_str()
            };
            ui.add(egui::Label::new(small(base, p.secondary)).truncate());
            ui.end_row();
        });

    // what happened to it, in log order
    ui.add_space(10.0);
    let mut history: Vec<(i64, String, String)> = Vec::new();
    for add in &detail.adds {
        let bytes: u64 = add.files.iter().filter(|f| !f.metadata_only).map(|f| f.size).sum();
        let count = add.files.len();
        let files = format!("{count} file{}", if count == 1 { "" } else { "s" });
        let mut text = format!("{files} added ({})", human_size(bytes));
        if !add.replaces.is_empty() {
            text += &format!(" · {} added again", add.replaces.len());
        }
        for mount in &add.mounts {
            text += &format!("\n{}", crate::container::mounts::mount_line(mount));
        }
        history.push((add.entry_id, add.utc.clone(), text));
    }
    for close in &detail.closes {
        let signed = if close.is_signed() { "signed" } else { "unsigned" };
        history.push((close.entry_id, close.utc.clone(), format!("closed · {signed}")));
    }
    for (entry_id, utc) in &detail.closed_without_file {
        history.push((*entry_id, utc.clone(), "closed without its file (missing)".into()));
    }
    for (entry_id, utc, paths) in &detail.damaged_closes {
        history.push((
            *entry_id,
            utc.clone(),
            format!("closed as damaged · {} not matching", plural(paths.len(), "file")),
        ));
    }
    for (entry_id, utc) in &detail.reopens {
        history.push((*entry_id, utc.clone(), "reopened".into()));
    }
    for (entry_id, ..) in &detail.late_signatures {
        history.push((*entry_id, String::new(), "signed later".into()));
    }
    history.sort();
    for (entry_id, utc, text) in &history {
        history_row(ui, utc, *entry_id, text, actions);
    }

    // its files
    ui.add_space(10.0);
    let files: Vec<_> = detail.files().map(|(_, file)| file).collect();
    ui.label(
        RichText::new(format!("FILES {}", files.len()))
            .size(SMALL_SIZE)
            .family(theme::bold())
            .color(p.muted)
            .extra_letter_spacing(1.2),
    );
    ui.separator();
    if files.is_empty() {
        ui.label(small("No files yet. Add files or a folder from the ⋯ menu.", p.muted));
        return;
    }
    let row_height = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
    // a long file list scrolls on its own, so the next container and the notes stay reachable
    egui::ScrollArea::vertical()
        .id_salt(("container-files", summary.id))
        .max_height(row_height * 12.0)
        .auto_shrink([false, true])
        .show_rows(ui, row_height, files.len(), |ui, range| {
            let width = ui.available_width();
            for file in &files[range] {
                ui.horizontal(|ui| {
                    ui.set_height(row_height);
                    let mut path = file.path.clone();
                    if file.metadata_only {
                        path += "  (metadata only)";
                    } else if let Some((from, to)) = file.excerpt {
                        path += &format!("  (excerpt {from}–{to})");
                    } else if let Some(target) = &file.link {
                        path += &format!("  → {target}");
                    }
                    ui.allocate_ui(egui::vec2(width * 0.42, row_height), |ui| {
                        ui.add(egui::Label::new(RichText::new(&path).color(p.text)).truncate())
                            .on_hover_text(&path);
                    });
                    ui.allocate_ui(egui::vec2(width * 0.15, row_height), |ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(small(human_size(file.size), p.secondary));
                        });
                    });
                    ui.allocate_ui(egui::vec2(width * 0.2, row_height), |ui| {
                        let modified = times.get(&file.arn).map(|t| short_time(t)).unwrap_or_default();
                        ui.label(small(modified, p.muted)).on_hover_text("Last written");
                    });
                    if !file.sha256.is_empty() {
                        let short = format!("{}…", &file.sha256[..16.min(file.sha256.len())]);
                        ui.label(RichText::new(short).size(MONO_SIZE).monospace().color(p.muted))
                            .on_hover_text(format!(
                                "SHA-256 {}\nSHA-1 {}\nMD5 {}",
                                file.sha256, file.sha1, file.md5
                            ));
                    }
                });
            }
        });
}

/// The result of Verify Container, beside the main window like Verify Case.
pub struct ContainerVerifyWindow {
    pub id: u64,
    pub report: ContainerReport,
    pub open: bool,
}

impl ContainerVerifyWindow {
    pub fn show(&mut self, ctx: &egui::Context, actions: &mut Vec<VerifyAction>) {
        let report = &self.report;
        let name = report
            .graph
            .as_ref()
            .zip(report.uuid.as_ref())
            .and_then(|(graph, uuid)| {
                graph
                    .first_value(&format!("aff4://{uuid}"), &format!("{FACTUM_NS}containerName"))
                    .map(str::to_string)
            })
            .unwrap_or_else(|| {
                report
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
        let heading = format!("Verify Container {name}");
        let offset = 24.0 * (self.id % 5) as f32;
        report_window(
            ctx,
            egui::Id::unique(("container-verify-window", self.id)),
            &heading,
            &mut self.open,
            [720.0, 480.0],
            offset,
            |ui| {
                let p = *theme::current(ui.ctx());
                let overall = report.overall();
                let fails: Vec<&Finding> = report.findings.iter().filter(|f| f.level == Level::Fail).collect();
                let warnings: Vec<&Finding> = report.findings.iter().filter(|f| f.level == Level::Warn).collect();
                let verdict = match overall {
                    Level::Ok => format!("{} files verified", report.checked_files),
                    Level::Warn => plural(warnings.len(), "warning"),
                    Level::Fail if warnings.is_empty() => plural(fails.len(), "failure"),
                    Level::Fail => format!(
                        "{}, {}",
                        plural(fails.len(), "failure"),
                        plural(warnings.len(), "warning")
                    ),
                };
                ui.label(
                    RichText::new(format!("{} {verdict}", verdict_mark(overall)))
                        .size(theme::NOTE_SIZE)
                        .family(theme::bold())
                        .color(verdict_color(ui, overall)),
                );
                let format = match report.format {
                    ContainerFormat::Factum => "AFF4-L v1.0, written by factum",
                    ContainerFormat::Aff4l => "AFF4-L v1.0, written by another tool",
                    ContainerFormat::Legacy => "AFF4 before AFF4-L v1.0 (not supported)",
                    ContainerFormat::NotAff4 => "not an AFF4 container",
                };
                ui.label(small(format!("{} · {format}", report.path.display()), p.muted));
                ui.separator();
                egui::ScrollArea::vertical().auto_shrink([false, true]).show(ui, |ui| {
                    for state in &report.states {
                        ui.label(RichText::new(&state.label).family(theme::bold()).color(p.text));
                        let gpg = match &state.gpg {
                            Some(check) => format!(
                                "GPG {} {} ({})",
                                if check.valid { "\u{2713}" } else { "\u{2717}" },
                                check.username.as_deref().unwrap_or("unknown signer"),
                                check.fingerprint.as_deref().unwrap_or("?")
                            ),
                            None => "GPG: no signature".into(),
                        };
                        ui.label(small(gpg, p.secondary));
                        if let Some(check) = &state.x509 {
                            ui.label(small(
                                format!(
                                    "X.509 {} {} · root {} ({}) · {}",
                                    if check.valid && check.trusted {
                                        "\u{2713}"
                                    } else {
                                        "\u{2717}"
                                    },
                                    check.signer_subject.as_deref().unwrap_or("unknown signer"),
                                    check.root_subject.as_deref().unwrap_or("unknown"),
                                    check.root_fingerprint.as_deref().unwrap_or("?"),
                                    check.status
                                ),
                                p.secondary,
                            ));
                        }
                        ui.label(small(
                            format!("{} files listed · SHA-256 {}", state.files, state.turtle_sha256),
                            p.muted,
                        ));
                        ui.add_space(4.0);
                    }
                    if let Some(log) = &report.log {
                        let state = match log.matches_close {
                            Some(n) => format!("Case log: container #{}, in the state of close {n}", log.container_id),
                            None => format!("Case log: container #{}, open", log.container_id),
                        };
                        ui.label(small(state, p.secondary));
                        for line in &log.recorded_after {
                            ui.label(small(format!("  recorded after it: {line}"), p.muted));
                        }
                        ui.add_space(4.0);
                    }
                    for (heading, list, open) in [("Failures", &fails, true), ("Warnings", &warnings, fails.is_empty())]
                    {
                        if list.is_empty() {
                            continue;
                        }
                        egui::CollapsingHeader::new(format!("{heading} {}", list.len()))
                            .default_open(open)
                            .show(ui, |ui| {
                                for finding in list.iter() {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(verdict_mark(finding.level))
                                                .color(verdict_color(ui, finding.level)),
                                        );
                                        ui.add(egui::Label::new(finding.message.as_str()).wrap());
                                        if let Some(entry_id) = finding.entry_id
                                            && IconButton::new(icons::SHOW, "Show entry").show(ui).clicked()
                                        {
                                            actions.push(VerifyAction::ShowEntry(entry_id));
                                        }
                                    });
                                }
                            });
                    }
                });
            },
        );
    }
}
