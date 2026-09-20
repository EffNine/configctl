//! Config-file discovery registry.
//!
//! P1 discovers and records config files; it does not parse them deeply.
//! The registry is extensible: adding a new file type is an append.

use configctl_core::limits::Limits;
use std::path::Path;

/// A config file type definition.
pub struct ConfigTypeDef {
    pub name: &'static str,
    /// Ecosystem hint.
    pub hint: &'static str,
    /// Classification of the file's sensitivity.
    pub classification: &'static str,
}

/// Built-in config-file registry.
pub const CONFIG_TYPES: &[&str] = &[
    ".gitignore",
    ".editorconfig",
    ".tool-versions",
    ".nvmrc",
    ".node-version",
    ".python-version",
    ".rust-toolchain",
    ".rust-toolchain.toml",
    "Makefile",
    "makefile",
    "justfile",
    "Dockerfile",
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "go.mod",
    "go.sum",
    "CMakeLists.txt",
    "pom.xml",
    "build.gradle",
    "settings.gradle",
    "composer.json",
    "Gemfile",
    "mix.exs",
];

/// Generic config-extension names that count as config files even when the
/// exact name is not in `CONFIG_TYPES`. This keeps the registry extensible
/// without treating every arbitrary filename as a config file.
pub const CONFIG_EXTS: &[&str] = &[".toml", ".yaml", ".yml", ".ini", ".conf", ".cfg"];

/// Match a filename to its config type (exact registry, then generic
/// extension). Returns `true` for discovery.
pub fn match_config_type(name: &str) -> bool {
    if CONFIG_TYPES.contains(&name) {
        return true;
    }
    CONFIG_EXTS.iter().any(|ext| name.ends_with(ext))
}

/// Metadata for one discovered config file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigFileRecord {
    pub path: String,
    pub name: String,
    pub project: Option<String>,
    pub size: u64,
    pub permissions: Option<u32>,
    pub tracked_by_git: crate::env::GitStatus,
    pub classification: String,
}

/// Process one config file (metadata only, no deep parsing in P1).
pub fn process_config_file(
    path: &Path,
    limits: &Limits,
    git_status: crate::env::GitStatus,
) -> Result<ConfigFileRecord, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let size = meta.len();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    if size > limits.max_file_bytes as u64 {
        return Ok(ConfigFileRecord {
            path: path.to_string_lossy().into_owned(),
            name,
            project: None,
            size,
            permissions: perm(&meta),
            tracked_by_git: git_status,
            classification: "config".into(),
        });
    }

    Ok(ConfigFileRecord {
        path: path.to_string_lossy().into_owned(),
        name,
        project: None,
        size,
        permissions: perm(&meta),
        tracked_by_git: git_status,
        classification: "config".into(),
    })
}

#[cfg(unix)]
fn perm(meta: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn perm(_meta: &std::fs::Metadata) -> Option<u32> {
    None
}
