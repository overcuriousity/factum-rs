//! Case reports (HTML, PDF, Markdown) and verification bundles.

pub mod bundle;
pub mod html;
pub mod markdown;
pub mod model;
pub mod pdf;

use std::path::{Path, PathBuf};

use crate::canonical::{compact_utc, utc_now};
use crate::error::{FactumError, Result};
use crate::seals::{REASON_EXPORT, safe_filename};
use crate::services::Factum;

pub const FORMATS: [&str; 4] = ["html", "pdf", "md", "bundle"];

impl Factum<'_> {
    /// Seals the case, verifies it and writes the requested formats; returns the written files.
    pub fn export(&self, case_id: i64, formats: &[&str], out_dir: &Path) -> Result<Vec<PathBuf>> {
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
        // seal first, so the report and the bundle describe exactly the sealed state
        let seal_id = self.seal(case_id, REASON_EXPORT)?;
        let report = self.verify_case(case_id, None)?;
        let exported_utc = utc_now();
        let seal = self.get_tree_head(seal_id)?.expect("the seal was just created");
        let model = self.build_model(report, seal, self.signer.active_key(), &exported_utc)?;
        // built by concatenation: case file numbers may contain dots, which with_extension would cut off
        let stem = format!(
            "{}_{}",
            safe_filename(&model.case.case_file),
            compact_utc(&exported_utc)
        );
        let html = html::render_html(&model, false).into_bytes();
        // borrowed from the model: nothing is copied for formats that do not write image files
        let images = markdown::image_files(&model);
        let image_dir = format!("{stem}_images");
        let pdf = if unique.contains(&"pdf") || unique.contains(&"bundle") {
            pdf::render_pdf(&model)
        } else {
            Vec::new()
        };
        let mut written = Vec::new();
        for (format, suffix, content) in [("html", ".html", &html), ("pdf", ".pdf", &pdf)] {
            if unique.contains(&format) {
                let path = out_dir.join(format!("{stem}{suffix}"));
                std::fs::write(&path, content)?;
                written.push(path);
            }
        }
        if unique.contains(&"md") {
            let path = out_dir.join(format!("{stem}.md"));
            std::fs::write(&path, markdown::render_markdown(&model, &image_dir))?;
            written.push(path);
            if !images.is_empty() {
                let folder = out_dir.join(&image_dir);
                std::fs::create_dir_all(&folder)?;
                for (name, bytes) in &images {
                    let path = folder.join(name);
                    std::fs::write(&path, bytes)?;
                    written.push(path);
                }
            }
        }
        if unique.contains(&"bundle") {
            // not the .md report's text: the bundle links its images under images/
            let markdown = markdown::render_markdown(&model, "images").into_bytes();
            let reports = [("report.html", html), ("report.pdf", pdf), ("report.md", markdown)];
            written.push(self.build_bundle(&model, &reports, &images, &out_dir.join(format!("{stem}.zip")))?);
        }
        Ok(written)
    }
}
