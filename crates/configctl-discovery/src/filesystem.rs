//! v1.1 filesystem mapping: broad dotfile discovery + project file roles.
//!
//! No tiny hardcoded allowlist: every dotfile under a scan root is
//! discovered, categorized by name/location heuristics, and classified with
//! evidence. Project content is mapped by role so generated/cache content is
//! recorded with an exclusion reason instead of being silently ignored.

use configctl_core::classify::{CaptureAction, ResourceClass};
use std::path::Path;

/// Dotfile category (heuristic, name/location based).
pub fn categorize_dotfile(name: &str) -> &'static str {
    match name {
        ".bashrc" | ".bash_profile" | ".bash_login" | ".profile" | ".bash_logout" => "shell",
        ".zshrc" | ".zprofile" | ".zlogin" | ".zlogout" | ".zshenv" => "shell",
        ".config" | ".local" | ".cache" => "xdg-base",
        s if s.starts_with(".fish") || s == "fish" => "shell",
        ".tmux.conf" | ".inputrc" | ".wgetrc" | ".curlrc" => "terminal",
        ".gitconfig" | ".gitignore" | ".gitattributes" | ".gitmodules" => "vcs",
        ".editorconfig" => "editor",
        ".vimrc" | ".gvimrc" | ".ideavimrc" => "editor",
        ".tool-versions" | ".nvmrc" | ".node-version" | ".python-version" => "toolchain",
        ".rust-toolchain" | ".rust-toolchain.toml" => "toolchain",
        ".envrc" => "direnv",
        ".ssh" => "credential",
        ".gnupg" => "credential",
        ".aws" | ".kube" => "credential",
        ".docker" => "container",
        _ => "unknown",
    }
}

/// One discovered dotfile with its verdict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DotfileRecord {
    pub path: String,
    pub name: String,
    pub category: String,
    pub classification: ResourceClass,
    pub action: CaptureAction,
    #[serde(default)]
    pub signals: Vec<String>,
    pub reason: String,
}

/// Project content role: `src/` is fundamentally different from `target/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectFileRole {
    Source,
    Configuration,
    Script,
    Toolchain,
    Manifest,
    Lockfile,
    Ci,
    Container,
    Documentation,
    EnvSchema,
    Generated,
    Cache,
    Dependency,
    Secret,
    Binary,
    Unknown,
}

impl ProjectFileRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ProjectFileRole::Source => "source",
            ProjectFileRole::Configuration => "configuration",
            ProjectFileRole::Script => "script",
            ProjectFileRole::Toolchain => "toolchain",
            ProjectFileRole::Manifest => "manifest",
            ProjectFileRole::Lockfile => "lockfile",
            ProjectFileRole::Ci => "ci",
            ProjectFileRole::Container => "container",
            ProjectFileRole::Documentation => "documentation",
            ProjectFileRole::EnvSchema => "env_schema",
            ProjectFileRole::Generated => "generated",
            ProjectFileRole::Cache => "cache",
            ProjectFileRole::Dependency => "dependency",
            ProjectFileRole::Secret => "secret",
            ProjectFileRole::Binary => "binary",
            ProjectFileRole::Unknown => "unknown",
        }
    }
}

/// Source-code extensions mapped without reading content.
const SOURCE_EXTS: &[&str] = &[
    "rs", "go", "py", "js", "ts", "tsx", "jsx", "mjs", "cjs", "c", "h", "hpp", "cc", "cpp", "cxx",
    "java", "kt", "kts", "scala", "rb", "php", "ex", "exs", "erl", "hrl", "hs", "ml", "mli", "swift",
    "m", "mm", "cs", "fs", "vb", "r", "jl", "lua", "pl", "pm", "sh", "bash", "zsh", "fish", "ps1",
    "sql", "graphql", "proto", "vue", "svelte", "astro", "dart", "nim", "zig", "v", "adb", "ads",
    "f90", "f", "for", "pas", "d", "cr", "elm", "purs", "clj", "cljs", "rkt", "scm",
];

const DOC_EXTS: &[&str] = &["md", "markdown", "rst", "txt", "adoc", "org", "tex"];

/// Role of one project-owned file (pure path heuristics + exec bit).
pub fn classify_project_file(path: &Path, executable: bool, size: u64) -> (ProjectFileRole, Vec<String>) {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let components: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let mut signals = Vec::new();

    // Generated / cache / dependency content first (recorded, not reproduced).
    if configctl_core::classify::GENERATED_DIRS
        .iter()
        .any(|d| components.iter().any(|c| c == *d))
    {
        signals.push("generated_dir".to_string());
        return (ProjectFileRole::Generated, signals);
    }
    if configctl_core::classify::CACHE_DIRS
        .iter()
        .any(|d| components.iter().any(|c| c == *d))
    {
        signals.push("cache_dir".to_string());
        return (ProjectFileRole::Cache, signals);
    }
    if components.iter().any(|c| c == ".git") {
        signals.push("vcs_metadata".to_string());
        return (ProjectFileRole::Dependency, signals);
    }
    if components.iter().any(|c| c == "vendor" || c == "third_party" || c == "third-party") {
        signals.push("vendored".to_string());
        return (ProjectFileRole::Dependency, signals);
    }
    // Env files / schemas (purpose first; secrecy is tracked orthogonally
    // by the env/secret pipeline, not by the content role).
    if crate::env::is_env_filename(&name) {
        signals.push("env_file".to_string());
        return (ProjectFileRole::EnvSchema, signals);
    }
    // Secrets by name (core registry: key basenames + extensions).
    if configctl_core::classify::SECRET_BASENAMES.iter().any(|b| *b == name)
        || configctl_core::classify::SECRET_EXTENSIONS.iter().any(|e| name.ends_with(e))
        || (name.starts_with("id_") && !name.contains('.'))
    {
        signals.push("secret_name".to_string());
        return (ProjectFileRole::Secret, signals);
    }
    // Lockfiles / manifests.
    if is_lockfile_name(&name) {
        signals.push("lockfile".to_string());
        return (ProjectFileRole::Lockfile, signals);
    }
    if is_manifest_name(&name) {
        signals.push("manifest".to_string());
        return (ProjectFileRole::Manifest, signals);
    }
    // CI / containers.
    if components.iter().any(|c| c == ".github" || c == ".circleci")
        || matches!(name.as_str(), ".gitlab-ci.yml" | "Jenkinsfile" | "Earthfile")
    {
        signals.push("ci".to_string());
        return (ProjectFileRole::Ci, signals);
    }
    if matches!(
        name.as_str(),
        "Dockerfile" | "Containerfile" | "compose.yaml" | "compose.yml" | "docker-compose.yml" | ".dockerignore"
    ) {
        signals.push("container".to_string());
        return (ProjectFileRole::Container, signals);
    }
    // Conventional source/script/config locations.
    if components.iter().any(|c| {
        matches!(
            c.as_str(),
            "src" | "lib" | "app" | "pkg" | "cmd" | "internal" | "tests" | "test" | "spec"
                | "benchmarks" | "benches" | "examples"
        )
    }) {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if SOURCE_EXTS.contains(&ext) {
                signals.push(format!("source_ext:.{ext}"));
                return (ProjectFileRole::Source, signals);
            }
        }
    }
    if components.iter().any(|c| c == "scripts" || c == "script" || c == ".devcontainer") || executable {
        if executable {
            signals.push("executable".to_string());
            return (ProjectFileRole::Script, signals);
        }
    }
    // Toolchain files.
    if matches!(
        name.as_str(),
        "Makefile" | "makefile" | "justfile" | "Justfile" | "Taskfile.yml" | "Taskfile.yaml"
            | "CMakeLists.txt" | "meson.build" | "BUILD" | "BUILD.bazel" | ".tool-versions" | ".envrc"
    ) {
        signals.push("toolchain_file".to_string());
        return (ProjectFileRole::Toolchain, signals);
    }
    // Extension-driven fallback.
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if SOURCE_EXTS.contains(&ext) {
            signals.push(format!("source_ext:.{ext}"));
            return (ProjectFileRole::Source, signals);
        }
        if DOC_EXTS.contains(&ext) {
            signals.push(format!("doc_ext:.{ext}"));
            return (ProjectFileRole::Documentation, signals);
        }
        if matches!(ext, "toml" | "yaml" | "yml" | "json" | "ini" | "conf" | "cfg" | "nix") {
            signals.push(format!("config_ext:.{ext}"));
            return (ProjectFileRole::Configuration, signals);
        }
    }
    // Large non-text-looking files are likely binary.
    if size > 1024 * 1024 && path.extension().is_none() {
        signals.push("large_no_extension".to_string());
        return (ProjectFileRole::Binary, signals);
    }
    signals.push("unclassified".to_string());
    (ProjectFileRole::Unknown, signals)
}

fn is_lockfile_name(name: &str) -> bool {
    matches!(
        name,
        "Cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "uv.lock"
            | "poetry.lock"
            | "Pdm.lock"
            | "go.sum"
            | "Gemfile.lock"
            | "composer.lock"
            | "mix.lock"
    )
}

fn is_manifest_name(name: &str) -> bool {
    matches!(
        name,
        "Cargo.toml"
            | "package.json"
            | "pyproject.toml"
            | "go.mod"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "Gemfile"
            | "composer.json"
            | "mix.exs"
            | "CMakeLists.txt"
            | "meson.build"
    )
}

/// Per-project content counts by role (lists stay out of JSON; counts + the
/// exclusion reasons are the forensic record).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ProjectContentSummary {
    pub project: String,
    pub path: String,
    pub roles: std::collections::BTreeMap<String, u64>,
    pub total: u64,
}
