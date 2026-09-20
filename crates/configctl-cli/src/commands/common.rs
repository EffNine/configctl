//! Shared CLI helpers: profile resolution.

use std::path::PathBuf;

/// Resolve an explicit profile argument (path or name) to a bundle directory.
pub fn resolve_profile_dir(arg: &str) -> PathBuf {
    super::plan::resolve_profile_dir(arg)
}

/// Default profiles directory (`$XDG_CONFIG_HOME/configctl/profiles`).
pub fn profiles_dir() -> PathBuf {
    if let Some(cfg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(cfg).join("configctl/profiles")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config/configctl/profiles")
    } else {
        PathBuf::from("profiles")
    }
}

/// Resolve an optional profile argument: explicit wins; otherwise the profiles
/// directory must contain exactly one profile (never guess among several).
pub fn resolve_profile_default(arg: Option<&str>) -> Result<PathBuf, String> {
    if let Some(a) = arg {
        if !a.is_empty() {
            return Ok(resolve_profile_dir(a));
        }
    }
    let dir = profiles_dir();
    let entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|_| {
            "no profile given and no profiles directory found (pass a PROFILE path or name)"
                .to_string()
        })?
        .filter_map(|e| e.ok().map(|c| c.path()))
        .filter(|p| p.join("profile.toml").exists())
        .collect();
    match entries.len() {
        1 => Ok(entries[0].clone()),
        0 => Err("no profile found (pass a PROFILE path or name)".into()),
        _ => Err("multiple profiles exist; pass an explicit PROFILE".into()),
    }
}
