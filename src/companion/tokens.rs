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

/// One way a section may be shortened. Steps of every section are applied one line at a time, the lowest
/// priority number first; a section without steps is never cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    /// drop lines while more than `keep` are left; `from_start` drops the oldest (first) lines, otherwise the last
    Lines {
        priority: u8,
        from_start: bool,
        keep: usize,
    },
    /// cut lines longer than `max_chars` down to it, ending in `…`, beginning at the `from_start` end
    Shorten {
        priority: u8,
        max_chars: usize,
        from_start: bool,
    },
}

impl Cut {
    fn priority(&self) -> u8 {
        match *self {
            Cut::Lines { priority, .. } | Cut::Shorten { priority, .. } => priority,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Section {
    pub name: &'static str,
    pub lines: Vec<String>,
    pub cuts: Vec<Cut>,
    pub kind: TextKind,
}

#[derive(Clone, Debug)]
pub struct Packed {
    pub text: String,
    /// lines dropped per section, for sections where any were
    pub cut: Vec<(&'static str, usize)>,
    /// lines shortened per section, for sections where any were
    pub shortened: Vec<(&'static str, usize)>,
    pub tokens: usize,
    /// the sections as packed; a section whose every line was dropped holds `CUT_MARKER`
    pub sections: Vec<Section>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BudgetError {
    /// every step was taken and the prompt still overflows; `section` is its largest section and `needed` the size
    /// of the whole prompt after every cut
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
                    "after every cut the prompt needs {needed} tokens, the budget is {budget}; the largest section is \
                     \"{section}\""
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

/// At most `max` characters, ending in `…` when cut.
pub fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

struct Work {
    name: &'static str,
    lines: VecDeque<String>,
    cuts: Vec<Cut>,
    kind: TextKind,
    /// characters of all lines plus one newline between each pair
    body_chars: usize,
    dropped: usize,
    shortened: usize,
}

impl Work {
    fn new(section: Section) -> Self {
        let body_chars =
            section.lines.iter().map(|l| l.chars().count()).sum::<usize>() + section.lines.len().saturating_sub(1);
        Self {
            name: section.name,
            lines: section.lines.into(),
            cuts: section.cuts,
            kind: section.kind,
            body_chars,
            dropped: 0,
            shortened: 0,
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

    /// The line `Shorten` would cut next: the first one too long, counted from its end.
    fn too_long(&self, max_chars: usize, from_start: bool) -> Option<usize> {
        let long = |i: &usize| self.lines[*i].chars().count() > max_chars;
        if from_start {
            (0..self.lines.len()).find(long)
        } else {
            (0..self.lines.len()).rev().find(long)
        }
    }

    fn can(&self, cut: &Cut) -> bool {
        match *cut {
            Cut::Lines { keep, .. } => self.lines.len() > keep,
            Cut::Shorten {
                max_chars, from_start, ..
            } => self.too_long(max_chars, from_start).is_some(),
        }
    }

    fn apply(&mut self, cut: Cut) {
        match cut {
            Cut::Lines { from_start, .. } => self.drop_line(from_start),
            Cut::Shorten {
                max_chars, from_start, ..
            } => {
                if let Some(i) = self.too_long(max_chars, from_start) {
                    let short = truncate(&self.lines[i], max_chars);
                    self.body_chars -= self.lines[i].chars().count() - short.chars().count();
                    self.lines[i] = short;
                    self.shortened += 1;
                }
            }
        }
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

    fn into_section(self) -> Section {
        let mut lines: Vec<String> = self.lines.into();
        if lines.is_empty() && self.dropped > 0 {
            lines.push(CUT_MARKER.to_string());
        }
        Section {
            name: self.name,
            lines,
            cuts: self.cuts,
            kind: self.kind,
        }
    }
}

/// Joins the sections as `## name\nlines\n\n`, taking one step at a time (lowest priority number first; on equal
/// priority the later section first) until the estimate fits `budget`. Only when no step is left is it refused.
pub fn pack(sections: Vec<Section>, budget: usize, cal: &Calibration) -> Result<Packed, BudgetError> {
    let mut work: Vec<Work> = sections.into_iter().map(Work::new).collect();
    let mut total: usize = work.iter().map(|w| w.tokens(cal)).sum();
    while total > budget {
        let step = work
            .iter()
            .enumerate()
            .flat_map(|(i, w)| w.cuts.iter().filter(|c| w.can(c)).map(move |&c| (i, c)))
            .min_by_key(|&(i, c)| (c.priority(), std::cmp::Reverse(i)));
        let Some((index, cut)) = step else {
            let section = work.iter().max_by_key(|w| w.tokens(cal)).map_or("", |w| w.name);
            return Err(BudgetError::Uncuttable {
                section,
                needed: total,
                budget,
            });
        };
        let before = work[index].tokens(cal);
        work[index].apply(cut);
        total = total - before + work[index].tokens(cal);
    }
    let mut text = String::new();
    for w in &work {
        w.render(&mut text);
    }
    let count = |n: fn(&Work) -> usize| {
        work.iter()
            .filter(|w| n(w) > 0)
            .map(|w| (w.name, n(w)))
            .collect::<Vec<_>>()
    };
    let cut = count(|w| w.dropped);
    let shortened = count(|w| w.shortened);
    Ok(Packed {
        text,
        cut,
        shortened,
        tokens: total,
        sections: work.into_iter().map(Work::into_section).collect(),
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
            cuts: vec![cut],
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
                        keep: 0,
                    },
                ),
                section(
                    "new",
                    "new",
                    Cut::Lines {
                        priority: 2,
                        from_start: true,
                        keep: 0,
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
    fn pack_refuses_only_when_no_step_is_left() {
        let pinned = Section {
            name: "pinned",
            lines: lines("pin", 20),
            cuts: Vec::new(),
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

    #[test]
    fn last_resort_steps_shorten_before_they_drop_and_keep_the_floor() {
        let make = || {
            vec![
                Section {
                    name: "pinned",
                    lines: vec!["p".repeat(300), "q".repeat(300)],
                    cuts: vec![
                        Cut::Shorten {
                            priority: 3,
                            max_chars: 60,
                            from_start: true,
                        },
                        Cut::Lines {
                            priority: 5,
                            from_start: true,
                            keep: 0,
                        },
                    ],
                    kind: TextKind::Prose,
                },
                Section {
                    name: "new",
                    lines: vec!["n".repeat(300), "m".repeat(300)],
                    cuts: vec![
                        Cut::Lines {
                            priority: 2,
                            from_start: false,
                            keep: 1,
                        },
                        Cut::Shorten {
                            priority: 4,
                            max_chars: 30,
                            from_start: false,
                        },
                    ],
                    kind: TextKind::Prose,
                },
            ]
        };
        let cal = Calibration::default();
        let full = pack(make(), usize::MAX, &cal).unwrap();

        // the newest entry goes, the oldest stays whole, the oldest pinned line is shortened
        let mild = pack(make(), full.tokens - 110, &cal).unwrap();
        assert_eq!(mild.cut, vec![("new", 1)]);
        assert_eq!(mild.shortened, vec![("pinned", 1)]);
        assert!(mild.text.contains(&format!("{}…\n{}", "p".repeat(59), "q".repeat(300))));
        assert!(mild.text.contains(&"n".repeat(300)));

        // at the floor: one pinned line dropped, the kept entry shortened, never dropped
        let tight = pack(make(), 25, &cal).unwrap();
        assert!(tight.tokens <= 25);
        assert_eq!(tight.cut, vec![("pinned", 2), ("new", 1)]);
        assert!(tight.text.contains(&format!("## new\n{}…", "n".repeat(29))));
        assert_eq!(tight.sections[0].lines, vec![CUT_MARKER.to_string()]);
        assert_eq!(tight.sections[1].lines.len(), 1);

        assert!(pack(make(), 10, &cal).is_err());
    }
}
