//! Case reports (HTML, PDF, Markdown) and verification bundles.

pub mod bundle;
pub mod html;
pub mod markdown;
pub mod model;
pub mod pdf;

use std::path::{Path, PathBuf};

use crate::canonical::{compact_utc, utc_now};
use crate::error::{FactumError, Result};
use crate::export::model::ReportModel;
use crate::files::safe_filename_capped;
use crate::seals::REASON_EXPORT;
use crate::services::Factum;
use crate::verifier::Level;

pub const FORMATS: [&str; 4] = ["html", "pdf", "md", "bundle"];

/// The case file number in an export's file names, in bytes; the time and a suffix come on top of it.
const NAME_MAX_BYTES: usize = 100;

/// What an export wrote.
#[derive(Debug)]
pub struct Exported {
    pub paths: Vec<PathBuf>,
    /// the verdict of the verification the files describe
    pub verdict: Level,
    /// what a reader of the files should know; the export itself worked
    pub warnings: Vec<String>,
}

/// The reports an export needs; one no format asks for stays empty. The HTML holds the images as base64.
#[derive(Debug)]
pub struct Rendered {
    pub html: Vec<u8>,
    pub pdf: Vec<u8>,
    /// the characters no font of the PDF has
    pub unsupported: Vec<char>,
}

/// Renders what the formats need: the bundle carries all reports.
pub fn render_needed(model: &ReportModel, formats: &[&str]) -> Rendered {
    let needed = |report: &str| formats.contains(&report) || formats.contains(&"bundle");
    let html = if needed("html") {
        html::render_html(model, false).into_bytes()
    } else {
        Vec::new()
    };
    let (pdf, unsupported) = if needed("pdf") {
        pdf::render_pdf_checked(model)
    } else {
        (Vec::new(), Vec::new())
    };
    Rendered { html, pdf, unsupported }
}

/// Moves the outputs from the staging folder into the target folder, all of them or none.
fn publish(staging: &Path, target: &Path, names: &[String]) -> Result<()> {
    for (index, name) in names.iter().enumerate() {
        if let Err(e) = std::fs::rename(staging.join(name), target.join(name)) {
            for moved in &names[..index] {
                let _ = std::fs::rename(target.join(moved), staging.join(moved));
            }
            return Err(e.into());
        }
    }
    Ok(())
}

impl Factum<'_> {
    /// Seals the case, verifies it and writes the requested formats; returns the written files.
    pub fn export(&self, case_id: i64, formats: &[&str], out_dir: &Path) -> Result<Vec<PathBuf>> {
        Ok(self.export_checked(case_id, formats, out_dir)?.paths)
    }

    /// Like [`export`](Self::export), with the verdict and the warnings. All files appear together at the end; an
    /// export that fails leaves none, only its seal.
    pub fn export_checked(&self, case_id: i64, formats: &[&str], out_dir: &Path) -> Result<Exported> {
        let mut unique: Vec<&str> = Vec::new();
        for format in formats {
            if !unique.contains(format) {
                unique.push(format);
            }
        }
        let unknown: Vec<&str> = unique.iter().copied().filter(|f| !FORMATS.contains(f)).collect();
        if !unknown.is_empty() || unique.is_empty() {
            let given = if unknown.is_empty() {
                "none given".to_string()
            } else {
                unknown.join(", ")
            };
            return Err(FactumError::general(format!(
                "Unknown export format(s): {given}. Use {}.",
                FORMATS.join(", ")
            )));
        }
        std::fs::create_dir_all(out_dir)?;
        // in the target folder: the outputs get there by a rename. Dropped, it takes everything in it along
        let staging = tempfile::Builder::new().prefix(".factum-export-").tempdir_in(out_dir)?;
        // seal first, so the report and the bundle describe exactly the sealed state
        let seal_id = self.seal(case_id, REASON_EXPORT)?;
        let report = self.verify_case(case_id, None)?;
        let verdict = report.overall();
        let exported_utc = utc_now();
        let seal = self.get_tree_head(seal_id)?.expect("the seal was just created");
        let model = self.build_model(report, seal, self.signer.active_key(), &exported_utc)?;
        // built by concatenation: case file numbers may contain dots, which with_extension would cut off
        let stem = format!(
            "{}_{}",
            safe_filename_capped(&model.case.case_file, NAME_MAX_BYTES),
            compact_utc(&exported_utc)
        );
        let Rendered { html, pdf, unsupported } = render_needed(&model, &unique);
        // borrowed from the model: nothing is copied for formats that do not write image files
        let images = markdown::image_files(&model);
        let image_dir = format!("{stem}_images");
        // what goes into out_dir, and the files that makes for the caller
        let mut outputs = Vec::new();
        let mut written = Vec::new();
        for (format, suffix, content) in [("html", ".html", &html), ("pdf", ".pdf", &pdf)] {
            if unique.contains(&format) {
                let name = format!("{stem}{suffix}");
                std::fs::write(staging.path().join(&name), content)?;
                written.push(out_dir.join(&name));
                outputs.push(name);
            }
        }
        if unique.contains(&"md") {
            let name = format!("{stem}.md");
            std::fs::write(
                staging.path().join(&name),
                markdown::render_markdown(&model, &image_dir),
            )?;
            written.push(out_dir.join(&name));
            outputs.push(name);
            if !images.is_empty() {
                let folder = staging.path().join(&image_dir);
                std::fs::create_dir(&folder)?;
                for (name, bytes) in &images {
                    std::fs::write(folder.join(name), bytes)?;
                    written.push(out_dir.join(&image_dir).join(name));
                }
                outputs.push(image_dir);
            }
        }
        if unique.contains(&"bundle") {
            // not the .md report's text: the bundle links its images under images/
            let markdown = markdown::render_markdown(&model, "images").into_bytes();
            let reports = [("report.html", html), ("report.pdf", pdf), ("report.md", markdown)];
            let name = format!("{stem}.zip");
            self.build_bundle(&model, &reports, &images, &staging.path().join(&name))?;
            written.push(out_dir.join(&name));
            outputs.push(name);
        }
        publish(staging.path(), out_dir, &outputs)?;
        Ok(Exported {
            paths: written,
            verdict,
            warnings: pdf::unsupported_warning(&unsupported).into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_rename_takes_back_what_was_moved() {
        let (staging, target) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        for name in ["a", "b"] {
            std::fs::write(staging.path().join(name), name).unwrap();
        }
        // a folder with something in it cannot be renamed over
        std::fs::create_dir_all(target.path().join("b").join("full")).unwrap();
        let names = ["a".to_string(), "b".to_string()];
        assert!(publish(staging.path(), target.path(), &names).is_err());
        assert!(!target.path().join("a").exists());
        assert_eq!(std::fs::read(staging.path().join("a")).unwrap(), b"a");
        std::fs::remove_dir_all(target.path().join("b")).unwrap();
        publish(staging.path(), target.path(), &names).unwrap();
        assert_eq!(std::fs::read(target.path().join("b")).unwrap(), b"b");
        assert_eq!(std::fs::read_dir(staging.path()).unwrap().count(), 0);
    }
}
