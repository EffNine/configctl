//! Project marker detection.
//!
//! A directory is considered a project when at least one recognizable
//! marker exists. Markers are a static, extensible registry: adding a new
//! ecosystem means appending to `MARKERS`, not changing the detector.

use std::collections::BTreeSet;

/// The VCS type detected from a project marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VcsType {
    #[default]
    Unknown,
    Git,
}

/// A project marker definition.
pub struct MarkerDef {
    pub name: &'static str,
    /// Marker is a directory.
    pub is_dir: bool,
    /// Ecosystem hint when this marker is present.
    pub hint: &'static str,
}

/// Built-in marker registry.
pub const MARKERS: &[MarkerDef] = &[
    MarkerDef {
        name: ".git",
        is_dir: true,
        hint: "",
    },
    MarkerDef {
        name: "Cargo.toml",
        is_dir: false,
        hint: "rust",
    },
    MarkerDef {
        name: "package.json",
        is_dir: false,
        hint: "javascript",
    },
    MarkerDef {
        name: "pyproject.toml",
        is_dir: false,
        hint: "python",
    },
    MarkerDef {
        name: "requirements.txt",
        is_dir: false,
        hint: "python",
    },
    MarkerDef {
        name: "go.mod",
        is_dir: false,
        hint: "go",
    },
    MarkerDef {
        name: "CMakeLists.txt",
        is_dir: false,
        hint: "cmake",
    },
    MarkerDef {
        name: "Makefile",
        is_dir: false,
        hint: "make",
    },
    MarkerDef {
        name: "pom.xml",
        is_dir: false,
        hint: "java",
    },
    MarkerDef {
        name: "build.gradle",
        is_dir: false,
        hint: "java",
    },
    MarkerDef {
        name: "composer.json",
        is_dir: false,
        hint: "php",
    },
    MarkerDef {
        name: "Gemfile",
        is_dir: false,
        hint: "ruby",
    },
    MarkerDef {
        name: "mix.exs",
        is_dir: false,
        hint: "elixir",
    },
];

/// Result of probing one directory for project markers.
#[derive(Debug, Default, Clone, serde::Serialize)]
#[serde(default)]
pub struct ProjectDetection {
    pub markers_found: Vec<String>,
    pub hints: Vec<String>,
    pub vcs: VcsType,
}

impl ProjectDetection {
    /// True when at least one marker was found.
    pub fn is_project(&self) -> bool {
        !self.markers_found.is_empty()
    }

    /// True when `.git` is the only marker found.
    pub fn markers_first_is_git(&self) -> bool {
        self.markers_found.len() == 1
            && self.markers_found.first().map(|s| s.as_str()) == Some(".git")
    }

    /// Confidence: `.git` plus at least one manifest yields "certain".
    pub fn confidence(&self) -> &'static str {
        if self.markers_found.iter().any(|m| m == ".git")
            && self
                .markers_found
                .iter()
                .any(|m| m != ".git" && m != ".gitignore" && m != ".gitmodules")
        {
            "certain"
        } else if !self.markers_found.is_empty() {
            "likely"
        } else {
            "unknown"
        }
    }
}

/// Probe `dir` for project markers by stat'ing each known marker.
pub fn detect_project(dir: &std::path::Path) -> ProjectDetection {
    let mut det = ProjectDetection::default();
    let mut hints: BTreeSet<&str> = BTreeSet::new();

    for m in MARKERS {
        let p = dir.join(m.name);
        let present = if m.is_dir { p.is_dir() } else { p.is_file() };
        if present {
            det.markers_found.push(m.name.to_string());
            if !m.hint.is_empty() {
                hints.insert(m.hint);
            }
        }
    }

    if det.markers_found.iter().any(|m| m == ".git") {
        det.vcs = VcsType::Git;
    }
    det.hints = hints.into_iter().map(String::from).collect();
    det.markers_found.sort();
    det
}
