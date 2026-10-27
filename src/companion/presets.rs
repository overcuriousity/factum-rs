//! The companion presets: an app-wide choice of the guideline (system prompt) and of the archetype definitions.

use super::prompts;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Preset {
    Forensics,
    Investigator,
    Osint,
    SourceCriticism,
    /// the guideline text the investigator wrote
    Custom,
}

/// One line per archetype; the names are fixed (they are stored with every question), the definitions differ.
pub type Archetypes = [(&'static str, &'static str); 7];

const FORENSICS_ARCHETYPES: Archetypes = [
    ("coverage", "what, where, when, how, who, prevention"),
    ("corroborate", "a trace that supports or refutes a thesis"),
    ("document", "a step just taken is not written down"),
    ("integrity", "chain of custody, hashes, unchanged evidence"),
    ("repeatability", "tool, version, parameters, method noted"),
    ("causality", "linking events, traces and actors"),
    (
        "phase",
        "what usually comes next, is a component's examination complete before analysis",
    ),
];

const INVESTIGATOR_ARCHETYPES: Archetypes = [
    ("coverage", "what, where, when, how, who, why"),
    ("corroborate", "a fact or source that supports or refutes a thesis"),
    (
        "document",
        "a step just taken or a fact just learned is not written down",
    ),
    (
        "integrity",
        "where a fact comes from, and that it is recorded unaltered",
    ),
    (
        "repeatability",
        "how a result was obtained, so that someone else could repeat it",
    ),
    ("causality", "linking events, facts and people"),
    (
        "phase",
        "what usually comes next, is a line of inquiry complete before conclusions rest on it",
    ),
];

const OSINT_ARCHETYPES: Archetypes = [
    (
        "coverage",
        "who, what, where, when, how, and through which accounts or identifiers",
    ),
    (
        "corroborate",
        "an independent source that supports or refutes a finding",
    ),
    ("document", "a finding or a pivot just made is not written down"),
    (
        "integrity",
        "source captured with URL, time and hash, an archived copy kept",
    ),
    ("repeatability", "tool, query, search terms and settings noted"),
    ("causality", "linking accounts, identifiers, events and actors"),
    (
        "phase",
        "which pivot usually comes next, is a lead exhausted before an attribution rests on it",
    ),
];

const SOURCE_CRITICISM_ARCHETYPES: Archetypes = [
    ("coverage", "who created the source, when, where, for whom and why"),
    (
        "corroborate",
        "an independent source that confirms or contradicts a statement",
    ),
    ("document", "an assessment just made is not written down"),
    ("integrity", "provenance, authenticity, the source unaltered"),
    (
        "repeatability",
        "how the source was found and assessed, so that the assessment can be checked",
    ),
    (
        "causality",
        "how sources depend on each other and on the events they describe",
    ),
    ("phase", "is a source fully assessed before conclusions rest on it"),
];

impl Preset {
    pub const ALL: [Preset; 5] = [
        Preset::Forensics,
        Preset::Investigator,
        Preset::Osint,
        Preset::SourceCriticism,
        Preset::Custom,
    ];

    /// The id stored in the settings.
    pub fn as_str(self) -> &'static str {
        match self {
            Preset::Forensics => "forensics",
            Preset::Investigator => "investigator",
            Preset::Osint => "osint",
            Preset::SourceCriticism => "source_criticism",
            Preset::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Option<Preset> {
        Self::ALL.into_iter().find(|preset| preset.as_str() == s.trim())
    }

    pub fn label(self) -> &'static str {
        match self {
            Preset::Forensics => "Forensics",
            Preset::Investigator => "Generic investigator",
            Preset::Osint => "OSINT research",
            Preset::SourceCriticism => "Source criticism",
            Preset::Custom => "Custom",
        }
    }

    pub fn blurb(self) -> &'static str {
        match self {
            Preset::Forensics => {
                "Digital forensics: integrity, chain of custody, repeatable methods, the phases of an investigation."
            }
            Preset::Investigator => {
                "Any investigation: the source of each fact, alternative explanations, documentation."
            }
            Preset::Osint => "Open-source research: preserving online sources, pivots, how certain an attribution is.",
            Preset::SourceCriticism => {
                "Work with documents and testimony: provenance, authenticity, bias, independent confirmation."
            }
            Preset::Custom => "Your own guideline text.",
        }
    }

    /// The guideline shipped with factum; None for Custom.
    pub fn builtin_guideline(self) -> Option<&'static str> {
        match self {
            Preset::Forensics => Some(prompts::DEFAULT_GUIDELINE),
            Preset::Investigator => Some(prompts::INVESTIGATOR_GUIDELINE),
            Preset::Osint => Some(prompts::OSINT_GUIDELINE),
            Preset::SourceCriticism => Some(prompts::SOURCE_CRITICISM_GUIDELINE),
            Preset::Custom => None,
        }
    }

    /// Custom uses the generic investigator's definitions.
    pub fn archetypes(self) -> &'static Archetypes {
        match self {
            Preset::Forensics => &FORENSICS_ARCHETYPES,
            Preset::Investigator | Preset::Custom => &INVESTIGATOR_ARCHETYPES,
            Preset::Osint => &OSINT_ARCHETYPES,
            Preset::SourceCriticism => &SOURCE_CRITICISM_ARCHETYPES,
        }
    }
}
