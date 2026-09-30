//! Read-only observation of machine state for planning/verification.
//!
//! Everything here is non-mutating: subprocesses go through `CommandRunner`
//! with fixed argv, file reads are bounded and symlink-safe (`symlink_metadata`
//! first, symlinks recorded — never followed for content).

use crate::command::{CommandRequest, CommandRunner};
use crate::paths;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// How a managed file target was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileObs {
    /// True when the path exists (any file type).
    pub exists: bool,
    /// True when the path (or any parent) is a symlink.
    pub is_symlink: bool,
    /// True when the existing path is a non-regular file (dir, fifo, ...).
    pub is_non_regular: bool,
    /// SHA-256 of content when a regular non-symlink file; `None` otherwise.
    pub content_hash: Option<String>,
    /// File length when known.
    pub len: Option<u64>,
}

/// Service state as observed via `systemctl --user`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceObs {
    pub exists: bool,
    pub enabled: Option<bool>,
    pub running: Option<bool>,
    pub unknown: bool,
}

/// Read-only snapshot of the machine slices relevant to a profile.
#[derive(Debug, Clone, Default)]
pub struct ObservedState {
    /// Installed apt packages (name → version) for tooling names only.
    pub packages: BTreeMap<String, String>,
    /// True when the package manager was unreachable.
    pub packages_unavailable: bool,
    /// Managed file targets (`~/...` as declared) → observation.
    pub files: BTreeMap<String, FileObs>,
    /// Git metadata (None when git unavailable).
    pub git_user_name: Option<String>,
    pub git_user_email: Option<String>,
    pub git_unavailable: bool,
    /// Services (unit → observation).
    pub services: BTreeMap<String, ServiceObs>,
    pub services_unavailable: bool,
    /// Secret refs declared by the profile → existence (via backend probe;
    /// `None` when the backend itself is unavailable).
    pub secret_exists: BTreeMap<String, Option<bool>>,
    /// Literal env entries read from the managed env file (name → value).
    pub env_literals: BTreeMap<String, String>,
    /// Literal env entries read from the canonical managed shell env file
    /// (`~/.config/configctl/env.sh`, v1.2); empty when it is absent.
    pub envfile_literals: BTreeMap<String, String>,
    /// True when the canonical managed shell env file exists.
    ///
    /// Deliberately *not* part of [`fingerprint`]: env-consolidation plans
    /// carry exact per-operation `expected_before` guards instead, so adding
    /// this field must not perturb existing plan hashes.
    pub envfile_present: bool,
}

/// Expand a `~/...` target against `home`. Returns `None` when the target is
/// invalid (caller records UNKNOWN rather than guessing).
pub fn expand_target(target: &str, home: &Path) -> Option<PathBuf> {
    if target == "~" {
        return Some(home.to_path_buf());
    }
    let rest = target.strip_prefix("~/")?;
    if rest.is_empty() || rest.contains('\0') {
        return None;
    }
    Some(home.join(rest))
}

/// Observe machine state for the slices a profile cares about.
///
/// - `apt_names`: desired package names (observation records installed
///   versions for exactly these names; nothing else is queried per-package).
/// - `file_targets`: declared `~/...` targets.
/// - `git_wanted`: whether to probe git config.
/// - `services`: desired unit names.
/// - `secret_refs`: declared secret refs (existence only; values never read).
/// - `env_names`: literal env names to read from the managed env file.
#[allow(clippy::too_many_arguments)]
pub fn observe(
    runner: &dyn CommandRunner,
    home: &Path,
    apt_names: &[String],
    file_targets: &[String],
    git_wanted: bool,
    services: &[String],
    secret_refs: &[String],
    secret_probe: &dyn Fn(&str) -> Option<bool>,
    env_names: &[String],
) -> ObservedState {
    let mut st = ObservedState::default();

    // Packages: one bounded `dpkg-query` call; parse only wanted names.
    {
        let wanted: std::collections::BTreeSet<&str> =
            apt_names.iter().map(|s| s.as_str()).collect();
        let req = CommandRequest::new("dpkg-query", ["-W", "-f=${Package}\t${Version}\n"])
            .output_cap(512 * 1024);
        match runner.run(&req) {
            Ok(o) if o.status == Some(0) => {
                for line in o.stdout.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let mut parts = line.split('\t');
                    let name = parts.next().unwrap_or("").trim();
                    let version = parts.next().unwrap_or("").trim();
                    if wanted.contains(name) && !version.is_empty() {
                        st.packages.insert(name.to_string(), version.to_string());
                    }
                }
            }
            _ => {
                st.packages_unavailable = true;
            }
        }
    }

    // Files.
    for t in file_targets {
        let obs = match expand_target(t, home) {
            Some(abs) => observe_file(&abs),
            None => FileObs {
                exists: false,
                is_symlink: false,
                is_non_regular: true,
                content_hash: None,
                len: None,
            },
        };
        st.files.insert(t.clone(), obs);
    }

    // Git.
    if git_wanted {
        let req =
            CommandRequest::new("git", ["config", "--global", "--list"]).output_cap(32 * 1024);
        match runner.run(&req) {
            Ok(o) if o.status == Some(0) => {
                for line in o.stdout.lines() {
                    let line = line.trim();
                    let Some(eq) = line.find('=') else { continue };
                    let key = line[..eq].trim().to_lowercase();
                    let value = line[eq + 1..].trim().to_string();
                    match key.as_str() {
                        "user.name" => st.git_user_name = Some(value),
                        "user.email" => st.git_user_email = Some(value),
                        _ => {}
                    }
                }
            }
            _ => st.git_unavailable = true,
        }
    }

    // Services via `systemctl --user`.
    if !services.is_empty() {
        // Probe manager once.
        let probe =
            CommandRequest::new("systemctl", ["--user", "list-units"]).output_cap(64 * 1024);
        let manager_ok = matches!(runner.run(&probe), Ok(o) if o.status == Some(0));
        if !manager_ok {
            st.services_unavailable = true;
            for s in services {
                st.services.insert(
                    s.clone(),
                    ServiceObs {
                        unknown: true,
                        ..Default::default()
                    },
                );
            }
        } else {
            for s in services {
                st.services.insert(s.clone(), observe_service(runner, s));
            }
        }
    }

    // Secrets: existence only.
    for r in secret_refs {
        st.secret_exists.insert(r.clone(), secret_probe(r));
    }

    // Env literals from the managed env file.
    {
        let env_file = home.join(".config/environment.d/90-configctl.conf");
        let current = read_env_file(&env_file);
        for n in env_names {
            if let Some(v) = current.get(n) {
                st.env_literals.insert(n.clone(), v.clone());
            }
        }
    }

    // Canonical managed shell env file (v1.2). Read-only and bounded; a
    // symlink or oversized file is reported as absent rather than followed.
    {
        let env_file = home.join(crate::envmap::CANONICAL_REL);
        if let Ok(meta) = std::fs::symlink_metadata(&env_file) {
            if meta.file_type().is_file() && meta.len() <= 64 * 1024 {
                if let Ok(bytes) = std::fs::read(&env_file) {
                    st.envfile_present = true;
                    if let Some(map) = crate::apply::parse_env_bytes(&bytes) {
                        st.envfile_literals = map;
                    }
                }
            }
        }
    }

    st
}

/// Observe one filesystem path without following symlinks.
pub fn observe_file(abs: &Path) -> FileObs {
    let meta = match std::fs::symlink_metadata(abs) {
        Ok(m) => m,
        Err(_) => {
            return FileObs {
                exists: false,
                is_symlink: false,
                is_non_regular: false,
                content_hash: None,
                len: None,
            };
        }
    };
    if meta.file_type().is_symlink() {
        return FileObs {
            exists: true,
            is_symlink: true,
            is_non_regular: false,
            content_hash: None,
            len: None,
        };
    }
    // Parent symlink components: fail closed.
    if has_symlink_parent(abs) {
        return FileObs {
            exists: true,
            is_symlink: true,
            is_non_regular: false,
            content_hash: None,
            len: None,
        };
    }
    if !meta.file_type().is_file() {
        return FileObs {
            exists: true,
            is_symlink: false,
            is_non_regular: true,
            content_hash: None,
            len: Some(meta.len()),
        };
    }
    if meta.len() > 256 * 1024 {
        return FileObs {
            exists: true,
            is_symlink: false,
            is_non_regular: false,
            content_hash: None,
            len: Some(meta.len()),
        };
    }
    let hash = std::fs::read(abs)
        .ok()
        .map(|b| crate::hash::file_content_hash(&b));
    FileObs {
        exists: true,
        is_symlink: false,
        is_non_regular: false,
        content_hash: hash,
        len: Some(meta.len()),
    }
}

/// True when any existing ancestor of `abs` is a symlink.
fn has_symlink_parent(abs: &Path) -> bool {
    let mut cur = abs.parent();
    while let Some(p) = cur {
        if let Ok(m) = std::fs::symlink_metadata(p) {
            if m.file_type().is_symlink() {
                return true;
            }
        } else {
            break;
        }
        cur = p.parent();
    }
    false
}

fn observe_service(runner: &dyn CommandRunner, unit: &str) -> ServiceObs {
    // Strict unit grammar (same as profile validation).
    if !paths::validate_service_unit(unit) {
        return ServiceObs {
            unknown: true,
            ..Default::default()
        };
    }
    let enabled = {
        let req =
            CommandRequest::new("systemctl", ["--user", "is-enabled", unit]).output_cap(8 * 1024);
        match runner.run(&req) {
            Ok(o) => match o.stdout.trim() {
                "enabled" => Some(true),
                "disabled" => Some(false),
                _ => None,
            },
            Err(_) => None,
        }
    };
    let running = {
        let req =
            CommandRequest::new("systemctl", ["--user", "is-active", unit]).output_cap(8 * 1024);
        match runner.run(&req) {
            Ok(o) => match o.stdout.trim() {
                "active" => Some(true),
                "inactive" | "failed" | "unknown" => Some(false),
                _ => None,
            },
            Err(_) => None,
        }
    };
    if enabled.is_none() && running.is_none() {
        return ServiceObs {
            unknown: true,
            ..Default::default()
        };
    }
    ServiceObs {
        exists: true,
        enabled,
        running,
        unknown: false,
    }
}

/// Read `KEY=VALUE` lines from the managed env file (best-effort, bounded).
fn read_env_file(path: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return map;
    };
    if !meta.file_type().is_file() || meta.len() > 64 * 1024 {
        return map;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return map;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(eq) = line.find('=') else { continue };
        let name = line[..eq].trim();
        let value = line[eq + 1..].trim();
        if crate::paths::validate_env_name(name).is_ok() {
            map.entry(name.to_string())
                .or_insert_with(|| value.to_string());
        }
    }
    map
}

/// Canonical observed-state fingerprint (sorted, no timestamps).
pub fn fingerprint(st: &ObservedState) -> String {
    let doc = serde_json::json!({
        "packages": st.packages,
        "packages_unavailable": st.packages_unavailable,
        "files": st.files.iter().map(|(k, v)| (k, serde_json::json!({
            "exists": v.exists,
            "is_symlink": v.is_symlink,
            "is_non_regular": v.is_non_regular,
            "content_hash": v.content_hash,
        }))).collect::<BTreeMap<_, _>>(),
        "git": {"name": st.git_user_name, "email": st.git_user_email},
        "services": st.services.iter().map(|(k, v)| (k, serde_json::json!({
            "exists": v.exists, "enabled": v.enabled,
            "running": v.running, "unknown": v.unknown,
        }))).collect::<BTreeMap<_, _>>(),
        "secret_exists": st.secret_exists,
        "env_literals": st.env_literals,
    });
    crate::hash::sha256_str(&serde_json::to_string(&doc).unwrap_or_default())
}
