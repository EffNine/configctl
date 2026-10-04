//! Package capture (read-only, Ubuntu/Debian `apt` via `dpkg-query`).
//!
//! Capture records name + installed version + architecture where available,
//! using only fixed argv through [`CommandRunner`]. No installation, no
//! mutation, no shell.
//!
//! ## Selection policy: `tooling-allowlist-v1`
//!
//! Capturing every OS package would produce an enormous, non-portable profile
//! (hundreds of base-system packages that are not reproducible intent).
//! Instead P2 captures the intersection of *installed* packages with an
//! explicit allowlist of recognized development/tooling packages.
//!
//! The allowlist is intentionally conservative and extensible: adding a new
//! tool means appending to [`TOOLING_ALLOWLIST`], not changing the capture
//! flow. The capture summary always reports how many installed packages were
//! *excluded* by the policy so the set is never silently pretended complete.

use crate::command::{CommandRequest, CommandRunner};
use crate::paths;

/// Selection policy identifier recorded in profile metadata.
pub const POLICY_ID: &str = "tooling-allowlist-v1";

/// Explicitly recognized development/tooling packages (apt names).
///
/// Kept sorted for determinism. Extend by appending (then re-sort).
pub const TOOLING_ALLOWLIST: &[&str] = &[
    "bat",
    "build-essential",
    "ca-certificates",
    "cargo",
    "cmake",
    "containerd",
    "curl",
    "docker.io",
    "fd-find",
    "fzf",
    "gcc",
    "git",
    "gnupg",
    "golang-go",
    "gradle",
    "htop",
    "jq",
    "make",
    "maven",
    "neovim",
    "nodejs",
    "npm",
    "openssh-client",
    "pkg-config",
    "postgresql-client",
    "python3",
    "python3-pip",
    "python3-venv",
    "ripgrep",
    "rustc",
    "shellcheck",
    "sqlite3",
    "tmux",
    "tree",
    "unzip",
    "vim",
    "wget",
    "yamllint",
    "yq",
    "zip",
];

/// True when `name` is a recognized tooling package.
pub fn is_tooling_package(name: &str) -> bool {
    TOOLING_ALLOWLIST.contains(&name)
}

/// One installed package observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
}

/// Raw capture result: what was observed vs. what was selected.
#[derive(Debug, Clone, Default)]
pub struct PackageCapture {
    /// Selected tooling packages (sorted, deduped, validated).
    pub selected: Vec<InstalledPackage>,
    /// Total installed packages observed (before policy filtering).
    pub installed_total: usize,
    /// Packages excluded by the allowlist policy.
    pub excluded_by_policy: usize,
    /// True when the package manager was unavailable (non-apt system,
    /// `dpkg-query` missing, parse failure). The profile then records no
    /// packages and the summary marks packages `unsupported`/`unknown`.
    pub unavailable: bool,
}

/// Query installed packages via fixed argv:
///
/// ```text
/// dpkg-query -W -f=${Package}\t${Version}\t${Architecture}\n
/// ```
///
/// No shell, bounded output, scrubbed environment (via `CommandRunner`).
pub fn capture_packages(runner: &dyn CommandRunner) -> PackageCapture {
    let req = CommandRequest::new(
        "dpkg-query",
        ["-W", "-f=${Package}\t${Version}\t${Architecture}\n"],
    )
    .output_cap(512 * 1024);
    let out = match runner.run(&req) {
        Ok(o) if o.status == Some(0) => o,
        _ => {
            return PackageCapture {
                unavailable: true,
                ..PackageCapture::default()
            };
        }
    };

    let mut all: Vec<InstalledPackage> = Vec::new();
    for line in out.stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split('\t');
        let name = parts.next().unwrap_or("").trim().to_string();
        let version = parts.next().unwrap_or("").trim().to_string();
        let arch = parts
            .next()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        if name.is_empty() || version.is_empty() {
            continue;
        }
        // Validate the name so adversarial `dpkg` output can never inject
        // shell syntax or traversal into the profile.
        if paths::validate_package_name(&name).is_err() {
            continue;
        }
        all.push(InstalledPackage {
            name,
            version,
            architecture: arch,
        });
    }
    // Deterministic: sort by name, dedupe (first version wins after sort).
    all.sort_by(|a, b| a.name.cmp(&b.name));
    all.dedup_by(|a, b| a.name == b.name);

    let installed_total = all.len();
    let mut selected: Vec<InstalledPackage> = all
        .into_iter()
        .filter(|p| is_tooling_package(&p.name))
        .collect();
    selected.sort_by(|a, b| a.name.cmp(&b.name));
    let excluded_by_policy = installed_total.saturating_sub(selected.len());

    PackageCapture {
        selected,
        installed_total,
        excluded_by_policy,
        unavailable: false,
    }
}

/// Names for `profile.toml [packages].apt` (sorted, unique).
pub fn apt_names(capture: &PackageCapture) -> Vec<String> {
    selected_names(capture)
}

/// Selected names (sorted, unique) for any native-manager capture.
/// Shared by `[packages].apt` / `.dnf` / `.pacman`.
pub fn selected_names(capture: &PackageCapture) -> Vec<String> {
    let mut names: Vec<String> = capture.selected.iter().map(|p| p.name.clone()).collect();
    names.sort();
    names.dedup();
    names
}
