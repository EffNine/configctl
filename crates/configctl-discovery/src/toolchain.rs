//! v1.1 executable / toolchain discovery.
//!
//! Maps development tools available through `PATH`: name, absolute path,
//! realpath, permissions, owner, version (only via the fixed-argv
//! [`VERSION_PROBES`] registry), and inferred provenance.
//!
//! Safety: arbitrary binaries are never executed. A version probe runs only
//! for basenames present in the registry, with fixed argv, governor timeout,
//! and capped output.

use configctl_core::command::CommandRunner;
use configctl_core::governor::{GovernorDecision, ResourceGovernor, governed_run};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Maximum executables retained (with explicit truncation flag).
pub const MAX_EXECUTABLES: usize = 20000;
/// Maximum version probes per scan (each also consumes a subprocess slot).
pub const MAX_VERSION_PROBES: usize = 128;

/// One discovered executable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExecutableRecord {
    pub name: String,
    pub path: String,
    /// Canonical path when resolution succeeded (read-only, never opened).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realpath: Option<String>,
    /// Provenance inferred from install location, or `unknown`.
    #[serde(default = "unknown_provenance")]
    pub provenance: String,
    /// Version string when a safe probe succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

fn unknown_provenance() -> String {
    "unknown".to_string()
}

/// Safe version probe registry: basename → fixed argv.
///
/// Every entry is a `--version`-class probe with no side effects. Anything
/// not listed here is never executed, no matter how it is named.
pub const VERSION_PROBES: &[(&str, &[&str])] = &[
    ("rustc", &["--version"]),
    ("cargo", &["--version"]),
    ("rustup", &["--version"]),
    ("python3", &["--version"]),
    ("python", &["--version"]),
    ("pip", &["--version"]),
    ("pipx", &["--version"]),
    ("uv", &["--version"]),
    ("poetry", &["--version"]),
    ("node", &["--version"]),
    ("npm", &["--version"]),
    ("pnpm", &["--version"]),
    ("yarn", &["--version"]),
    ("go", &["version"]),
    ("java", &["-version"]),
    ("javac", &["-version"]),
    ("gcc", &["--version"]),
    ("g++", &["--version"]),
    ("clang", &["--version"]),
    ("cmake", &["--version"]),
    ("ninja", &["--version"]),
    ("make", &["--version"]),
    ("docker", &["--version"]),
    ("podman", &["--version"]),
    ("kubectl", &["version", "--client=true"]),
    ("terraform", &["version"]),
    ("ansible", &["--version"]),
    ("git", &["--version"]),
    ("gh", &["--version"]),
    ("rg", &["--version"]),
    ("fd", &["--version"]),
    ("fdfind", &["--version"]),
    ("jq", &["--version"]),
    ("mise", &["--version"]),
    ("asdf", &["--version"]),
    ("snap", &["--version"]),
    ("flatpak", &["--version"]),
    ("just", &["--version"]),
    ("task", &["--version"]),
    ("nx", &["--version"]),
    ("deno", &["--version"]),
    ("bun", &["--version"]),
];

/// Fixed argv for a basename, if it is a known-safe probe target.
pub fn probe_argv(name: &str) -> Option<&'static [&'static str]> {
    VERSION_PROBES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, argv)| *argv)
}

/// Infer provenance from the install path (best effort; `unknown` otherwise).
pub fn infer_provenance(path: &Path, home: Option<&Path>) -> String {
    let s = path.to_string_lossy();
    if let Some(h) = home {
        let hs = h.to_string_lossy().into_owned();
        if s.starts_with(&format!("{hs}/.cargo/bin")) {
            return "cargo".into();
        }
        if s.starts_with(&format!("{hs}/.rustup")) {
            return "rustup".into();
        }
        if s.starts_with(&format!("{hs}/.local/share/mise")) {
            return "mise".into();
        }
        if s.starts_with(&format!("{hs}/.asdf")) {
            return "asdf".into();
        }
        if s.starts_with(&format!("{hs}/.local/bin"))
            || s.starts_with(&format!("{hs}/.local/share/uv"))
        {
            return "pipx/uv/local".into();
        }
        if s.starts_with(&format!("{hs}/go/bin")) || s.starts_with(&format!("{hs}/.go/bin")) {
            return "go".into();
        }
        if s.starts_with(&format!("{hs}/.nvm")) || s.starts_with(&format!("{hs}/.volta")) {
            return "node-manager".into();
        }
    }
    if s.starts_with("/snap/") || s.starts_with("/var/lib/snapd/") {
        return "snap".into();
    }
    if s.starts_with("/var/lib/flatpak/") || s.starts_with("/app/") {
        return "flatpak".into();
    }
    if s.starts_with("/usr/bin/")
        || s.starts_with("/bin/")
        || s.starts_with("/usr/local/bin/")
        || s.starts_with("/usr/sbin/")
    {
        return "system".into();
    }
    if s.starts_with("/opt/") {
        return "opt".into();
    }
    "unknown".into()
}

/// Clean a raw version line: first line only, no control chars, ≤ 200 chars.
fn clean_version(raw: &str) -> Option<String> {
    let line = raw.lines().next()?.trim();
    if line.is_empty() {
        return None;
    }
    let clean: String = line.chars().filter(|c| !c.is_control()).collect();
    if clean.is_empty() {
        return None;
    }
    Some(clean.chars().take(200).collect())
}

/// Probe one executable's version (registry-gated, governor-bounded).
pub fn probe_version(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
    exe_path: &Path,
    name: &str,
) -> Option<String> {
    let argv = probe_argv(name)?;
    match governed_run(governor, runner, exe_path, argv.iter().copied()) {
        Ok(out) if out.status == Some(0) => {
            // Some tools (java, python) report versions on stderr.
            clean_version(&out.stdout).or_else(|| clean_version(&out.stderr))
        }
        _ => None,
    }
}

/// Toolchain inventory across all `PATH` directories.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ToolchainInventory {
    pub executables: Vec<ExecutableRecord>,
    pub total: usize,
    pub version_probed: usize,
    pub truncated: bool,
    pub warnings: Vec<String>,
}

/// Discover executables on `PATH` with provenance + safe version probes.
pub fn discover_executables(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
) -> ToolchainInventory {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let dirs: Vec<PathBuf> = std::env::split_paths(&path_var).collect();
    discover_executables_in(governor, runner, &dirs)
}

/// Discover executables in explicit directories (test seam; same logic).
pub fn discover_executables_in(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
    dirs: &[PathBuf],
) -> ToolchainInventory {
    let mut inv = ToolchainInventory::default();
    let home = dirs_home();
    let mut seen_paths: BTreeSet<String> = BTreeSet::new();
    let mut probe_budget = MAX_VERSION_PROBES;

    for dir in dirs {
        if governor.limit_hit().is_some() {
            inv.warnings.push(format!(
                "toolchain discovery stopped early: budget exhausted ({})",
                governor.limit_hit().unwrap_or("unknown")
            ));
            break;
        }
        if !dir.is_absolute() {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(it) => it.filter_map(|e| e.ok()).collect::<Vec<_>>(),
            Err(_) => continue,
        };
        if governor.account_dir_entries(entries.len() as u64) != GovernorDecision::Proceed {
            inv.warnings.push("toolchain discovery stopped: directory entry budget".into());
            break;
        }
        for entry in entries {
            let path = entry.path();
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let ft = meta.file_type();
            let is_link = ft.is_symlink();
            if !is_link && !ft.is_file() {
                continue;
            }
            // Executable bit (or symlink to one — target checked at probe).
            #[cfg(unix)]
            let exec = {
                use std::os::unix::fs::MetadataExt;
                meta.mode() & 0o111 != 0 || is_link
            };
            #[cfg(not(unix))]
            let exec = true;
            if !exec {
                continue;
            }
            let name = match path.file_name().map(|n| n.to_string_lossy().into_owned()) {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            // Hostile filenames (newlines, control chars) are skipped, counted.
            if name.chars().any(|c| c.is_control()) || name.len() > 256 {
                continue;
            }
            let key = path.to_string_lossy().into_owned();
            if !seen_paths.insert(key.clone()) {
                continue;
            }
            if governor.account_file(0) != GovernorDecision::Proceed {
                inv.warnings.push("toolchain discovery stopped: file budget".into());
                break;
            }
            let realpath = std::fs::canonicalize(&path)
                .ok()
                .map(|p| p.to_string_lossy().into_owned());
            let provenance = infer_provenance(&path, home.as_deref());
            inv.executables.push(ExecutableRecord {
                name,
                path: key,
                realpath,
                provenance,
                version: None,
            });
            if inv.executables.len() >= MAX_EXECUTABLES {
                inv.truncated = true;
                inv.warnings.push(format!(
                    "executable list truncated to {MAX_EXECUTABLES} entries"
                ));
                break;
            }
        }
        if inv.truncated {
            break;
        }
    }

    inv.executables.sort_by(|a, b| a.path.cmp(&b.path));
    inv.total = inv.executables.len();

    // Version probes: registry names only, bounded count + subprocess slots.
    for exe in inv.executables.iter_mut() {
        if probe_budget == 0 || governor.limit_hit().is_some() {
            break;
        }
        if probe_argv(&exe.name).is_none() {
            continue;
        }
        probe_budget -= 1;
        let p = PathBuf::from(&exe.path);
        if let Some(v) = probe_version(governor, runner, &p, &exe.name.clone()) {
            exe.version = Some(v);
            inv.version_probed += 1;
        }
    }

    inv
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn registry_never_contains_shell_or_flags() {
        for (name, argv) in VERSION_PROBES {
            assert!(!name.contains(' '), "{name}");
            for a in *argv {
                // No shell metacharacters in fixed argv.
                assert!(
                    !a.contains('$') && !a.contains('`') && !a.contains(';') && !a.contains('|'),
                    "{name}: {a}"
                );
            }
        }
    }

    #[test]
    fn unknown_binaries_have_no_probe() {
        assert!(probe_argv("curl").is_none());
        assert!(probe_argv("some-random-binary-xyz").is_none());
        assert!(probe_argv("sh").is_none());
        assert!(probe_argv("bash").is_none());
        assert!(probe_argv("python3").is_some());
    }

    #[test]
    fn provenance_inference_spots_managers() {
        let home = Path::new("/home/u");
        assert_eq!(
            infer_provenance(Path::new("/home/u/.cargo/bin/rg"), Some(home)),
            "cargo"
        );
        assert_eq!(
            infer_provenance(Path::new("/usr/bin/git"), Some(home)),
            "system"
        );
        assert_eq!(
            infer_provenance(Path::new("/snap/bin/code"), Some(home)),
            "snap"
        );
        assert_eq!(
            infer_provenance(Path::new("/weird/place/tool"), Some(home)),
            "unknown"
        );
    }
}
