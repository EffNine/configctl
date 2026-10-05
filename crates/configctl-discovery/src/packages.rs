//! v1.1 package/toolchain provenance mapping.
//!
//! apt is not the whole universe: this module probes every package manager
//! that can be queried with fixed argv through the governor-bounded runner,
//! and records `provenance: unknown` whenever ownership cannot be
//! established. Never installs, never mutates, never shells out.

use configctl_core::command::CommandRunner;
use configctl_core::governor::{governed_run, ResourceGovernor};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Maximum entries retained per manager (with explicit truncation flag).
pub const MAX_PER_MANAGER: usize = 5000;
/// Maximum packages retained in the whole inventory.
pub const MAX_TOTAL: usize = 20000;

/// One installed package observation with provenance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PackageRecord {
    pub name: String,
    /// Version string when the manager reported one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Architecture when the manager reported one (dpkg, snap, flatpak).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Manager that reported it: `apt`, `dnf`, `pacman`, `apk`, `snap`,
    /// `flatpak`, `cargo`, `rustup`, `npm`, `pip`, `pipx`, `uv`, `go`,
    /// `mise`, `asdf`.
    pub manager: String,
    /// Install location when known (e.g. `~/.cargo/bin`, bundle path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// `explicit` when the manager distinguishes requested vs automatic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explicit: Option<bool>,
    /// Provenance source, or `unknown` when it cannot be established.
    #[serde(default = "unknown_provenance")]
    pub provenance: String,
}

fn unknown_provenance() -> String {
    "unknown".to_string()
}

/// Per-manager probe outcome.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManagerStatus {
    pub manager: String,
    pub available: bool,
    pub count: usize,
    #[serde(default)]
    pub truncated: bool,
}

/// Whole-machine package inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct PackageInventory {
    pub packages: Vec<PackageRecord>,
    pub managers: Vec<ManagerStatus>,
    pub total: usize,
    pub truncated: bool,
    pub warnings: Vec<String>,
}

/// Keep names to a safe alphabet; drop anything else (hostile manager
/// output can never inject traversal or shell syntax into the profile).
fn sanitize_name(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 128 {
        return None;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '/' | '-' | '_' | '+' | '.'))
    {
        return None;
    }
    if s.contains("..") {
        return None;
    }
    Some(s.to_string())
}

/// Strip control characters and cap version length.
fn sanitize_version(raw: &str) -> Option<String> {
    let s: String = raw.trim().chars().filter(|c| !c.is_control()).collect();
    if s.is_empty() {
        return None;
    }
    Some(s.chars().take(64).collect())
}

/// Probe one manager; returns its records plus a truncated flag.
fn probe(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
    program: &str,
    args: &[&str],
    parse: impl Fn(&str) -> Vec<PackageRecord>,
) -> (Vec<PackageRecord>, bool, bool) {
    let out = match governed_run(governor, runner, program, args.iter().copied()) {
        Ok(o) if o.status == Some(0) => o,
        _ => return (Vec::new(), false, false),
    };
    let mut records = parse(&out.stdout);
    let truncated = records.len() > MAX_PER_MANAGER;
    if truncated {
        records.truncate(MAX_PER_MANAGER);
    }
    (records, true, truncated || out.truncated)
}

fn apt_parse(text: &str) -> Vec<PackageRecord> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Some(name), Some(version)) = (sanitize_name(name), sanitize_version(version)) else {
            continue;
        };
        let arch = parts.next().and_then(sanitize_name);
        out.push(PackageRecord {
            name,
            version: Some(version),
            arch,
            manager: "apt".into(),
            location: None,
            explicit: None,
            provenance: "dpkg".into(),
        });
    }
    out
}

/// Pinned `rpm -qa --queryformat '%{NAME}\t%{EVR}\t%{ARCH}\n'` output:
/// `name\t[epoch:]version-release[\tarch]`. Epochs are preserved verbatim
/// for lock comparison; malformed lines are skipped, never guessed.
fn dnf_parse(text: &str) -> Vec<PackageRecord> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split('\t');
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Some(name), Some(version)) = (sanitize_name(name), sanitize_version(version)) else {
            continue;
        };
        let arch = parts.next().and_then(sanitize_name);
        out.push(PackageRecord {
            name,
            version: Some(version),
            arch,
            manager: "dnf".into(),
            location: None,
            explicit: None,
            provenance: "rpm".into(),
        });
    }
    out
}

/// `pacman -Q` output: `name version` per line (exactly two fields; names
/// and versions never contain whitespace).
fn pacman_parse(text: &str) -> Vec<PackageRecord> {
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() != 2 {
            continue;
        }
        let (Some(name), Some(version)) = (sanitize_name(cols[0]), sanitize_version(cols[1]))
        else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version: Some(version),
            arch: None,
            manager: "pacman".into(),
            location: None,
            explicit: None,
            provenance: "pacman".into(),
        });
    }
    out
}

/// `apk info -v` output: `name-version-rN` per line (Alpine). Names may
/// contain hyphens, so parse right-to-left: strip the trailing `-r<digits>`
/// revision, then split at the last hyphen whose suffix starts with a
/// digit. Lines that do not match are skipped, never guessed (the full
/// version, revision included, is preserved).
fn apk_parse(text: &str) -> Vec<PackageRecord> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((rest, revision)) = line.rsplit_once('-') else {
            continue;
        };
        let Some(digits) = revision.strip_prefix('r') else {
            continue;
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Some((name, version)) = rest.rsplit_once('-') else {
            continue;
        };
        if !version.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let (Some(name), Some(version)) = (
            sanitize_name(name),
            sanitize_version(&format!("{version}-{revision}")),
        ) else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version: Some(version),
            arch: None,
            manager: "apk".into(),
            location: None,
            explicit: None,
            provenance: "apk".into(),
        });
    }
    out
}

fn snap_parse(text: &str) -> Vec<PackageRecord> {
    // `snap list`: `Name  Version  Rev  Tracking  Publisher  Notes`
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        let (Some(name), Some(version)) = (sanitize_name(cols[0]), sanitize_version(cols[1]))
        else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version: Some(version),
            arch: None,
            manager: "snap".into(),
            location: Some("/snap".into()),
            explicit: None,
            provenance: "snapd".into(),
        });
    }
    out
}

fn flatpak_parse(text: &str) -> Vec<PackageRecord> {
    // `flatpak list --app --columns=application,version[,arch]`
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        let (Some(name), version, arch) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let Some(name) = sanitize_name(name) else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version: version.and_then(sanitize_version),
            arch: arch.and_then(sanitize_name),
            manager: "flatpak".into(),
            location: None,
            explicit: None,
            provenance: "flatpak".into(),
        });
    }
    out
}

fn cargo_parse(text: &str) -> Vec<PackageRecord> {
    // `cargo install --list` headers: `name vX.Y.Z:` followed by indented
    // `binary (executable)` detail lines (skipped).
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let line = line.trim();
        if line.is_empty() || !line.ends_with(':') {
            continue;
        }
        let mut parts = line.trim_end_matches(':').split_whitespace();
        let (Some(name), version_tok, rest) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if rest.is_some() {
            continue;
        }
        let version = version_tok
            .map(|v| v.trim_start_matches('v'))
            .and_then(sanitize_version);
        let Some(name) = sanitize_name(name) else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version,
            arch: None,
            manager: "cargo".into(),
            location: Some("~/.cargo/bin".into()),
            explicit: Some(true),
            provenance: "crates.io".into(),
        });
    }
    out
}

fn rustup_parse(text: &str) -> Vec<PackageRecord> {
    // `rustup toolchain list`: `stable-x86_64-unknown-linux-gnu (default)`
    let mut out = Vec::new();
    for line in text.lines() {
        let name = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(|c| c == '(' || c == ')');
        let Some(name) = sanitize_name(name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        out.push(PackageRecord {
            name,
            version: None,
            arch: None,
            manager: "rustup".into(),
            location: Some("~/.rustup/toolchains".into()),
            explicit: Some(true),
            provenance: "rustup".into(),
        });
    }
    out
}

fn npm_parse(text: &str) -> Vec<PackageRecord> {
    // `npm ls -g --depth=0`: tree lines ending in `name@version`.
    let mut out = Vec::new();
    for line in text.lines() {
        let token = line.split_whitespace().last().unwrap_or("");
        let Some((name, version)) = token.rsplit_once('@') else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let (Some(name), Some(version)) = (sanitize_name(name), sanitize_version(version)) else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version: Some(version),
            arch: None,
            manager: "npm".into(),
            location: None,
            explicit: Some(true),
            provenance: "npm".into(),
        });
    }
    out
}

fn freeze_parse(manager: &str, provenance: &str, text: &str) -> Vec<PackageRecord> {
    // `pip list --format=freeze`: `name==version`.
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((name, version)) = line.split_once("==") else {
            continue;
        };
        let (Some(name), Some(version)) = (sanitize_name(name), sanitize_version(version)) else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version: Some(version),
            arch: None,
            manager: manager.into(),
            location: None,
            explicit: None,
            provenance: provenance.into(),
        });
    }
    out
}

fn pipx_parse(text: &str) -> Vec<PackageRecord> {
    // `pipx list --short`: `package 1.2.3, installed using Python ...`
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        let (Some(name), version) = (
            sanitize_name(cols[0]),
            sanitize_version(cols[1].trim_end_matches(',')),
        ) else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version,
            arch: None,
            manager: "pipx".into(),
            location: Some("~/.local/bin".into()),
            explicit: Some(true),
            provenance: "pipx".into(),
        });
    }
    out
}

fn uv_parse(text: &str) -> Vec<PackageRecord> {
    // `uv tool list`: `name vX.Y.Z`
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        let (Some(name), version) = (
            sanitize_name(cols[0]),
            sanitize_version(cols[1].trim_start_matches('v')),
        ) else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version,
            arch: None,
            manager: "uv".into(),
            location: Some("~/.local/bin".into()),
            explicit: Some(true),
            provenance: "uv".into(),
        });
    }
    out
}

fn mise_parse(text: &str) -> Vec<PackageRecord> {
    // `mise ls`: `plugin  version  source  requested` (header line skipped).
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        if cols[0] == "Plugin" && cols[1] == "Version" {
            continue;
        }
        let (Some(name), version) = (sanitize_name(cols[0]), sanitize_version(cols[1])) else {
            continue;
        };
        out.push(PackageRecord {
            name,
            version,
            arch: None,
            manager: "mise".into(),
            location: Some("~/.local/share/mise".into()),
            explicit: Some(true),
            provenance: "mise".into(),
        });
    }
    out
}

fn asdf_parse(text: &str) -> Vec<PackageRecord> {
    // `asdf list`: plugin headers, then two-space-indented versions.
    let mut out = Vec::new();
    let mut plugin: Option<String> = None;
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(p) = &plugin {
                if let Some(version) = sanitize_version(line.trim()) {
                    out.push(PackageRecord {
                        name: p.clone(),
                        version: Some(version),
                        arch: None,
                        manager: "asdf".into(),
                        location: Some("~/.asdf".into()),
                        explicit: Some(true),
                        provenance: "asdf".into(),
                    });
                }
            }
        } else {
            plugin = sanitize_name(line);
        }
    }
    out
}

/// Collect the whole-machine package inventory across all managers.
///
/// Every probe is governor-bounded (spawn slot, timeout, output cap).
/// Managers that are missing or fail are recorded unavailable — never fatal.
pub fn collect_packages(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
) -> PackageInventory {
    let mut inv = PackageInventory::default();

    // (manager, program, argv)
    let probes: Vec<(&str, &str, Vec<&str>)> = vec![
        (
            "apt",
            "dpkg-query",
            vec!["-W", "-f=${Package}\t${Version}\t${Architecture}\n"],
        ),
        (
            "dnf",
            "rpm",
            vec!["-qa", "--queryformat", "%{NAME}\t%{EVR}\t%{ARCH}\n"],
        ),
        ("pacman", "pacman", vec!["-Q"]),
        ("apk", "apk", vec!["info", "-v"]),
        ("snap", "snap", vec!["list"]),
        (
            "flatpak",
            "flatpak",
            vec!["list", "--app", "--columns=application,version,arch"],
        ),
        ("cargo", "cargo", vec!["install", "--list"]),
        ("rustup", "rustup", vec!["toolchain", "list"]),
        ("npm", "npm", vec!["ls", "-g", "--depth=0"]),
        ("pip", "pip", vec!["list", "--format=freeze"]),
        ("pipx", "pipx", vec!["list", "--short"]),
        ("uv", "uv", vec!["tool", "list"]),
        ("mise", "mise", vec!["ls"]),
        ("asdf", "asdf", vec!["list"]),
    ];

    for (manager, program, args) in &probes {
        let parse = |text: &str| match *manager {
            "apt" => apt_parse(text),
            "dnf" => dnf_parse(text),
            "pacman" => pacman_parse(text),
            "apk" => apk_parse(text),
            "snap" => snap_parse(text),
            "flatpak" => flatpak_parse(text),
            "cargo" => cargo_parse(text),
            "rustup" => rustup_parse(text),
            "npm" => npm_parse(text),
            "pip" => freeze_parse("pip", "pypi", text),
            "pipx" => pipx_parse(text),
            "uv" => uv_parse(text),
            "mise" => mise_parse(text),
            "asdf" => asdf_parse(text),
            _ => Vec::new(),
        };
        let (mut records, available, truncated) = probe(governor, runner, program, args, parse);
        if available {
            for r in records.iter_mut() {
                if r.provenance == "unknown" {
                    r.provenance = manager.to_string();
                }
            }
            inv.managers.push(ManagerStatus {
                manager: manager.to_string(),
                available: true,
                count: records.len(),
                truncated,
            });
            inv.packages.append(&mut records);
        } else {
            inv.managers.push(ManagerStatus {
                manager: manager.to_string(),
                available: false,
                count: 0,
                truncated: false,
            });
        }
        if governor.limit_hit().is_some() {
            inv.warnings.push(format!(
                "package discovery stopped early: budget exhausted ({})",
                governor.limit_hit().unwrap_or("unknown")
            ));
            break;
        }
    }

    inv.packages
        .sort_by(|a, b| (&a.manager, &a.name).cmp(&(&b.manager, &b.name)));
    inv.packages
        .dedup_by(|a, b| a.manager == b.manager && a.name == b.name);
    inv.total = inv.packages.len();
    if inv.packages.len() > MAX_TOTAL {
        inv.packages.truncate(MAX_TOTAL);
        inv.truncated = true;
        inv.warnings.push(format!(
            "package inventory truncated to {MAX_TOTAL} entries"
        ));
    }
    inv.managers.sort_by(|a, b| a.manager.cmp(&b.manager));
    inv
}

/// Provenance counts by manager (`manager → count`), for reports.
pub fn provenance_summary(inv: &PackageInventory) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for p in &inv.packages {
        *m.entry(p.manager.clone()).or_insert(0) += 1;
    }
    m
}
