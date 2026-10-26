//! Token estimates and the packing of prompt sections into a budget.

use std::collections::VecDeque;
use std::fmt;

/// An entry line is cut at this many characters.
pub const MAX_LINE_CHARS: usize = 2000;

/// The window assumed when neither the settings nor the endpoint's listing name one, so an unknown endpoint never
/// overflows.
pub const DEFAULT_CONTEXT_WINDOW: u32 = 16_000;

const PROSE_CHARS_PER_TOKEN: f64 = 3.0;
/// Dense text (JSON, identifiers) needs more tokens: the prose ratio times this.
const DENSE_FACTOR: f64 = 0.8;
/// What a section shows once every line was cut.
pub const CUT_MARKER: &str = "(cut for space)";
const EMPTY_MARKER: &str = "(none)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextKind {
    Prose,
    Dense,
}

fn ceil_tokens(chars: usize, chars_per_token: f64) -> usize {
    // the epsilon keeps exact quotients such as 24 / 2.4 from rounding up
    (chars as f64 / chars_per_token - 1e-9).ceil().max(0.0) as usize
}

/// chars/3.0 for prose, chars/2.4 for dense text, rounded up.
pub fn estimate_tokens(text: &str, kind: TextKind) -> usize {
    Calibration::default().estimate_chars(text.chars().count(), kind)
}

/// The chars-per-token ratio of prose, recalibrated from usage counts the server reports.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Calibration {
    pub chars_per_token: f32,
}

impl Default for Calibration {
    fn default() -> Self {
        Self {
            chars_per_token: PROSE_CHARS_PER_TOKEN as f32,
        }
    }
}

impl Calibration {
    /// Takes the observed ratio, clamped to 1.5..=5.0; an empty observation is ignored.
    pub fn observe(&mut self, chars: usize, tokens: u32) {
        if chars > 0 && tokens > 0 {
            self.chars_per_token = (chars as f32 / tokens as f32).clamp(1.5, 5.0);
        }
    }

    /// The tokens of the text at this ratio, rounded up.
    pub fn estimate(&self, text: &str, kind: TextKind) -> usize {
        self.estimate_chars(text.chars().count(), kind)
    }

    fn estimate_chars(&self, chars: usize, kind: TextKind) -> usize {
        let prose = f64::from(self.chars_per_token);
        ceil_tokens(
            chars,
            if kind == TextKind::Dense {
                prose * DENSE_FACTOR
            } else {
                prose
            },
        )
    }
}

/// How a section may be shortened. A lower priority number is cut first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    Never,
    /// `from_start` drops the oldest (first) lines, otherwise the last ones
    Lines {
        priority: u8,
        from_start: bool,
    },
}

#[derive(Clone, Debug)]
pub struct Section {
    pub name: &'static str,
    pub lines: Vec<String>,
    pub cut: Cut,
    pub kind: TextKind,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Packed {
    pub text: String,
    /// lines dropped per section, for sections where any were
    pub cut: Vec<(&'static str, usize)>,
    pub tokens: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BudgetError {
    /// `section` is the largest section that cannot be cut; `needed` is the size of the whole prompt after every cut
    Uncuttable {
        section: &'static str,
        needed: usize,
        budget: usize,
    },
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uncuttable {
                section,
                needed,
                budget,
            } => {
                write!(
                    f,
                    "section \"{section}\" cannot be cut: the prompt needs {needed} tokens, the budget is {budget}"
                )
            }
        }
    }
}

impl std::error::Error for BudgetError {}

/// `0.8 × context_window − output_reserve`, never negative.
pub fn budget(context_window: u32, output_reserve: usize) -> usize {
    (context_window as usize * 4 / 5).saturating_sub(output_reserve)
}

struct Work {
    name: &'static str,
    lines: VecDeque<String>,
    cut: Cut,
    kind: TextKind,
    /// characters of all lines plus one newline between each pair
    body_chars: usize,
    dropped: usize,
}

impl Work {
    fn new(section: Section) -> Self {
        let body_chars =
            section.lines.iter().map(|l| l.chars().count()).sum::<usize>() + section.lines.len().saturating_sub(1);
        Self {
            name: section.name,
            lines: section.lines.into(),
            cut: section.cut,
            kind: section.kind,
            body_chars,
            dropped: 0,
        }
    }

    fn placeholder(&self) -> &'static str {
        if self.dropped > 0 { CUT_MARKER } else { EMPTY_MARKER }
    }

    /// Characters of the rendered `## name\n<body>\n\n`.
    fn rendered_chars(&self) -> usize {
        let body = if self.lines.is_empty() {
            self.placeholder().chars().count()
        } else {
            self.body_chars
        };
        "## ".len() + self.name.chars().count() + 1 + body + 2
    }

    fn tokens(&self, cal: &Calibration) -> usize {
        cal.estimate_chars(self.rendered_chars(), self.kind)
    }

    fn drop_line(&mut self, from_start: bool) {
        let line = if from_start {
            self.lines.pop_front()
        } else {
            self.lines.pop_back()
        };
        if let Some(line) = line {
            self.body_chars -= line.chars().count() + usize::from(!self.lines.is_empty());
            if self.lines.is_empty() {
                self.body_chars = 0;
            }
            self.dropped += 1;
        }
    }

    fn render(&self, out: &mut String) {
        out.push_str("## ");
        out.push_str(self.name);
        out.push('\n');
        if self.lines.is_empty() {
            out.push_str(self.placeholder());
        } else {
            let lines: Vec<&str> = self.lines.iter().map(String::as_str).collect();
            out.push_str(&lines.join("\n"));
        }
        out.push_str("\n\n");
    }
}

/// Joins the sections as `## name\nlines\n\n`, dropping lines one at a time (lowest priority number first, from
/// the section's chosen end; on equal priority the later section first) until the estimate fits `budget`.
pub fn pack(sections: Vec<Section>, budget: usize, cal: &Calibration) -> Result<Packed, BudgetError> {
    let mut work: Vec<Work> = sections.into_iter().map(Work::new).collect();
    let mut total: usize = work.iter().map(|w| w.tokens(cal)).sum();
    while total > budget {
        let victim = work
            .iter()
            .enumerate()
            .filter(|(_, w)| !w.lines.is_empty())
            .filter_map(|(i, w)| match w.cut {
                Cut::Lines { priority, from_start } => Some((priority, std::cmp::Reverse(i), i, from_start)),
                Cut::Never => None,
            })
            .min();
        let Some((_, _, index, from_start)) = victim else {
            let section = work
                .iter()
                .filter(|w| w.cut == Cut::Never)
                .max_by_key(|w| w.tokens(cal))
                .or_else(|| work.iter().max_by_key(|w| w.tokens(cal)))
                .map_or("", |w| w.name);
            return Err(BudgetError::Uncuttable {
                section,
                needed: total,
                budget,
            });
        };
        let before = work[index].tokens(cal);
        work[index].drop_line(from_start);
        total = total - before + work[index].tokens(cal);
    }
    let mut text = String::new();
    for w in &work {
        w.render(&mut text);
    }
    let cut = work
        .iter()
        .filter(|w| w.dropped > 0)
        .map(|w| (w.name, w.dropped))
        .collect();
    Ok(Packed {
        text,
        cut,
        tokens: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(tag: &str, n: usize) -> Vec<String> {
        (1..=n).map(|i| format!("{tag}-{i} {}", "x".repeat(25))).collect()
    }

    fn section(name: &'static str, tag: &str, cut: Cut) -> Section {
        Section {
            name,
            lines: lines(tag, 4),
            cut,
            kind: TextKind::Prose,
        }
    }

    #[test]
    fn estimate_uses_kind_ratio() {
        assert_eq!(estimate_tokens(&"a".repeat(30), TextKind::Prose), 10);
        assert_eq!(estimate_tokens(&"a".repeat(24), TextKind::Dense), 10);
    }

    #[test]
    fn budget_formula() {
        assert_eq!(budget(32_000, 1500), 24_100);
    }

    #[test]
    fn pack_cuts_lowest_priority_first_from_the_right_end() {
        let make = || {
            vec![
                section(
                    "related",
                    "rel",
                    Cut::Lines {
                        priority: 1,
                        from_start: false,
                    },
                ),
                section(
                    "new",
                    "new",
                    Cut::Lines {
                        priority: 2,
                        from_start: true,
                    },
                ),
            ]
        };
        let cal = Calibration::default();
        let full = pack(make(), usize::MAX, &cal).unwrap();
        assert!(full.cut.is_empty());

        let one = pack(make(), full.tokens - 1, &cal).unwrap();
        assert!(one.text.contains("rel-3") && !one.text.contains("rel-4"));
        assert!(one.text.contains("new-1"));
        assert_eq!(one.cut, vec![("related", 1)]);

        let many = pack(make(), full.tokens - 45, &cal).unwrap();
        assert!(many.text.contains("## related\n(cut for space)"));
        assert!(!many.text.contains("new-1") && many.text.contains("new-4"));
        assert!(many.tokens <= full.tokens - 45);
    }

    #[test]
    fn pack_refuses_when_uncuttable_overflows() {
        let pinned = Section {
            name: "pinned",
            lines: lines("pin", 20),
            cut: Cut::Never,
            kind: TextKind::Prose,
        };
        let err = pack(vec![pinned], 10, &Calibration::default()).unwrap_err();
        assert!(matches!(
            err,
            BudgetError::Uncuttable {
                section: "pinned",
                budget: 10,
                ..
            }
        ));
    }
}
