//! Evidence containers in the GUI: their menu, the view of one container, opening its folder.

use std::path::Path;

use egui::{Align, Layout, RichText};

use super::icons;
use super::theme::{self, MONO_SIZE, SMALL_SIZE};
use super::widgets::{self, IconButton};
use crate::container::volume::AddProgress;
use crate::containers::{ContainerDetail, ContainerSummary, human_size};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerAction {
    AddFiles(i64),
    AddFolder(i64),
    Close(i64),
    Reopen(i64),
    Verify(i64),
    Locate(i64),
    ShowInFolder(i64),
    /// a log entry of the container, shown in the case log
    ShowEntry(i64),
}

/// The container's menu: (label, action, enabled), with None between groups.
pub fn menu_items(summary: &ContainerSummary, archived: bool) -> Vec<(&'static str, ContainerAction, bool)> {
    let id = summary.id;
    let writable = summary.open && !archived && !summary.missing;
    vec![
        ("Add Files…", ContainerAction::AddFiles(id), writable),
        ("Add Folder…", ContainerAction::AddFolder(id), writable),
        ("Close Container", ContainerAction::Close(id), writable),
        (
            "Reopen Container",
            ContainerAction::Reopen(id),
            !summary.open && !archived,
        ),
        ("Verify Container…", ContainerAction::Verify(id), !summary.missing),
        ("Locate…", ContainerAction::Locate(id), summary.missing),
        ("Show in Folder", ContainerAction::ShowInFolder(id), !summary.missing),
    ]
}

/// The menu as the tree's context menu and the view's ⋯ button show it.
pub fn menu(ui: &mut egui::Ui, summary: &ContainerSummary, archived: bool, actions: &mut Vec<ContainerAction>) {
    for (index, (label, action, enabled)) in menu_items(summary, archived).into_iter().enumerate() {
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

/// The tree row's text: the name, and that it is open.
pub fn tree_label(summary: &ContainerSummary) -> String {
    if summary.open {
        format!("{} · open", summary.name)
    } else {
        summary.name.clone()
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

/// The view of one container, in place of the log: what it is, what happened to it, its files.
pub fn container_view(
    ui: &mut egui::Ui,
    detail: &ContainerDetail,
    evidence: Option<&str>,
    archived: bool,
    actions: &mut Vec<ContainerAction>,
) {
    let p = *theme::current(ui.ctx());
    let summary = &detail.summary;
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(&summary.name)
                .family(theme::bold())
                .size(16.0)
                .color(p.text),
        );
        ui.label(small(if summary.open { "open" } else { "closed" }, p.muted));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            IconButton::new(icons::MORE, "Container actions").menu(ui, |ui| menu(ui, summary, archived, actions));
        });
    });
    ui.add_space(4.0);
    egui::Grid::new("container-facts")
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
            if let Some(evidence) = evidence {
                ui.label(small("Evidence", p.muted));
                ui.label(small(evidence, p.secondary));
                ui.end_row();
            }
            ui.label(small("Base path", p.muted));
            ui.add(egui::Label::new(small(&detail.base_path, p.secondary)).truncate());
            ui.end_row();
        });

    // what happened to it, in log order
    ui.add_space(10.0);
    let mut history: Vec<(i64, String, String)> = Vec::new();
    for add in &detail.adds {
        let bytes: u64 = add.files.iter().filter(|f| !f.metadata_only).map(|f| f.size).sum();
        let count = add.files.len();
        let files = format!("{count} file{}", if count == 1 { "" } else { "s" });
        history.push((
            add.entry_id,
            add.utc.clone(),
            format!("{files} added ({})", human_size(bytes)),
        ));
    }
    for close in &detail.closes {
        let signed = if close.is_signed() { "signed" } else { "unsigned" };
        history.push((close.entry_id, close.utc.clone(), format!("closed · {signed}")));
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
    egui::ScrollArea::vertical()
        .id_salt("container-files")
        .auto_shrink([false, false])
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
                    ui.allocate_ui(egui::vec2(width * 0.55, row_height), |ui| {
                        ui.add(egui::Label::new(RichText::new(&path).color(p.text)).truncate())
                            .on_hover_text(&path);
                    });
                    ui.allocate_ui(egui::vec2(width * 0.15, row_height), |ui| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(small(human_size(file.size), p.secondary));
                        });
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
