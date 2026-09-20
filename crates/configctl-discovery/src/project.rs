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
    Mercurial,
    Subversion,
    Jujutsu,
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
    // --- v1.1 hardcore extension: VCS roots ---
    MarkerDef {
        name: ".hg",
        is_dir: true,
        hint: "",
    },
    MarkerDef {
        name: ".svn",
        is_dir: true,
        hint: "",
    },
    MarkerDef {
        name: ".jj",
        is_dir: true,
        hint: "",
    },
    MarkerDef {
        name: ".gitignore",
        is_dir: false,
        hint: "",
    },
    MarkerDef {
        name: ".gitmodules",
        is_dir: false,
        hint: "",
    },
    MarkerDef {
        name: ".gitattributes",
        is_dir: false,
        hint: "",
    },
    // --- lockfiles ---
    MarkerDef {
        name: "Cargo.lock",
        is_dir: false,
        hint: "rust",
    },
    MarkerDef {
        name: "package-lock.json",
        is_dir: false,
        hint: "javascript",
    },
    MarkerDef {
        name: "pnpm-lock.yaml",
        is_dir: false,
        hint: "javascript",
    },
    MarkerDef {
        name: "yarn.lock",
        is_dir: false,
        hint: "javascript",
    },
    MarkerDef {
        name: "pnpm-workspace.yaml",
        is_dir: false,
        hint: "javascript",
    },
    MarkerDef {
        name: ".nvmrc",
        is_dir: false,
        hint: "javascript",
    },
    MarkerDef {
        name: ".node-version",
        is_dir: false,
        hint: "javascript",
    },
    MarkerDef {
        name: "uv.lock",
        is_dir: false,
        hint: "python",
    },
    MarkerDef {
        name: "poetry.lock",
        is_dir: false,
        hint: "python",
    },
    MarkerDef {
        name: "Pdm.lock",
        is_dir: false,
        hint: "python",
    },
    MarkerDef {
        name: "setup.py",
        is_dir: false,
        hint: "python",
    },
    MarkerDef {
        name: "setup.cfg",
        is_dir: false,
        hint: "python",
    },
    MarkerDef {
        name: "tox.ini",
        is_dir: false,
        hint: "python",
    },
    MarkerDef {
        name: "go.sum",
        is_dir: false,
        hint: "go",
    },
    MarkerDef {
        name: "go.work",
        is_dir: false,
        hint: "go",
    },
    MarkerDef {
        name: "Gemfile.lock",
        is_dir: false,
        hint: "ruby",
    },
    MarkerDef {
        name: "composer.lock",
        is_dir: false,
        hint: "php",
    },
    MarkerDef {
        name: "mix.lock",
        is_dir: false,
        hint: "elixir",
    },
    // --- build systems / workspace manifests ---
    MarkerDef {
        name: "meson.build",
        is_dir: false,
        hint: "meson",
    },
    MarkerDef {
        name: "BUILD",
        is_dir: false,
        hint: "bazel",
    },
    MarkerDef {
        name: "BUILD.bazel",
        is_dir: false,
        hint: "bazel",
    },
    MarkerDef {
        name: "WORKSPACE",
        is_dir: false,
        hint: "bazel",
    },
    MarkerDef {
        name: "CMakePresets.json",
        is_dir: false,
        hint: "cmake",
    },
    MarkerDef {
        name: "settings.gradle",
        is_dir: false,
        hint: "java",
    },
    MarkerDef {
        name: "build.gradle.kts",
        is_dir: false,
        hint: "java",
    },
    MarkerDef {
        name: "gradlew",
        is_dir: false,
        hint: "java",
    },
    MarkerDef {
        name: ".cargo",
        is_dir: true,
        hint: "rust",
    },
    MarkerDef {
        name: "rust-toolchain.toml",
        is_dir: false,
        hint: "rust",
    },
    // --- task runners ---
    MarkerDef {
        name: "justfile",
        is_dir: false,
        hint: "just",
    },
    MarkerDef {
        name: "Justfile",
        is_dir: false,
        hint: "just",
    },
    MarkerDef {
        name: "Taskfile.yml",
        is_dir: false,
        hint: "task",
    },
    MarkerDef {
        name: "Taskfile.yaml",
        is_dir: false,
        hint: "task",
    },
    MarkerDef {
        name: "Earthfile",
        is_dir: false,
        hint: "earthly",
    },
    MarkerDef {
        name: "flake.nix",
        is_dir: false,
        hint: "nix",
    },
    MarkerDef {
        name: "devenv.nix",
        is_dir: false,
        hint: "nix",
    },
    MarkerDef {
        name: "shell.nix",
        is_dir: false,
        hint: "nix",
    },
    MarkerDef {
        name: ".tool-versions",
        is_dir: false,
        hint: "mise",
    },
    MarkerDef {
        name: ".envrc",
        is_dir: false,
        hint: "direnv",
    },
    // --- containers ---
    MarkerDef {
        name: "Dockerfile",
        is_dir: false,
        hint: "container",
    },
    MarkerDef {
        name: "Containerfile",
        is_dir: false,
        hint: "container",
    },
    MarkerDef {
        name: "compose.yaml",
        is_dir: false,
        hint: "container",
    },
    MarkerDef {
        name: "compose.yml",
        is_dir: false,
        hint: "container",
    },
    MarkerDef {
        name: "docker-compose.yml",
        is_dir: false,
        hint: "container",
    },
    MarkerDef {
        name: ".dockerignore",
        is_dir: false,
        hint: "container",
    },
    // --- CI configuration ---
    MarkerDef {
        name: ".github",
        is_dir: true,
        hint: "ci",
    },
    MarkerDef {
        name: ".gitlab-ci.yml",
        is_dir: false,
        hint: "ci",
    },
    MarkerDef {
        name: "Jenkinsfile",
        is_dir: false,
        hint: "ci",
    },
    // --- editor / project configuration ---
    MarkerDef {
        name: ".editorconfig",
        is_dir: false,
        hint: "editor",
    },
    MarkerDef {
        name: ".vscode",
        is_dir: true,
        hint: "editor",
    },
];

/// Markers that never declare a project root on their own.
///
/// Weak markers (editor config, toolchain pins, VCS auxiliary files) enrich
/// a project when a strong marker is present, but a directory containing
/// only weak markers is configuration — not a buildable unit. This keeps
/// broad discovery (the files are still mapped as dotfiles/configs) without
/// promoting every config dir into a project with capture semantics.
pub const WEAK_MARKERS: &[&str] = &[
    ".editorconfig",
    ".vscode",
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".tool-versions",
    ".envrc",
    ".gitignore",
    ".gitmodules",
    ".gitattributes",
    ".dockerignore",
    ".cargo",
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
    /// True when at least one *strong* marker was found.
    ///
    /// Weak markers (editor/toolchain/VCS-auxiliary files) never declare a
    /// project on their own; the directory is still fully mapped as
    /// configuration, just without project capture semantics.
    pub fn is_project(&self) -> bool {
        self.markers_found
            .iter()
            .any(|m| !WEAK_MARKERS.contains(&m.as_str()))
    }

    /// True when `.git` is the only marker found.
    pub fn markers_first_is_git(&self) -> bool {
        self.markers_found.len() == 1
            && self.markers_found.first().map(|s| s.as_str()) == Some(".git")
    }

    /// Confidence: `.git` plus at least one manifest yields "certain".
    pub fn confidence(&self) -> &'static str {
        if self.markers_found.iter().any(|m| m == ".git")
            && self.markers_found.iter().any(|m| {
                m != ".git" && m != ".gitignore" && m != ".gitmodules" && m != ".gitattributes"
            })
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
    } else if det.markers_found.iter().any(|m| m == ".hg") {
        det.vcs = VcsType::Mercurial;
    } else if det.markers_found.iter().any(|m| m == ".svn") {
        det.vcs = VcsType::Subversion;
    } else if det.markers_found.iter().any(|m| m == ".jj") {
        det.vcs = VcsType::Jujutsu;
    }
    det.hints = hints.into_iter().map(String::from).collect();
    det.markers_found.sort();
    det
}
