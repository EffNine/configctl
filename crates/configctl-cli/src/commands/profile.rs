//! `configctl profile list|show|validate|migrate` — read-only except migrate.
//!
//! - `list`: name, path, schema version, description.
//! - `show`: canonical, redacted rendering (profiles cannot contain values by
//!   construction — only literals that passed secret validation, refs, and
//!   metadata — so rendering the canonical TOML is safe).
//! - `validate`: parse + semantic validation; all errors listed; exit 2 when
//!   invalid. No mutation.
//! - `migrate`: v1 is the only schema this build supports. `--to 1` on a
//!   valid v1 profile is a verified no-op; any other target is refused with
//!   exit 2 and an explanation. No silent in-place interpretation.

use std::path::PathBuf;

/// One listed profile.
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub name: String,
    pub path: PathBuf,
    pub schema_version: u32,
    pub description: Option<String>,
}

/// List profiles in the profiles directory.
pub fn run_list(profiles_dir: Option<&str>) -> Result<Vec<ProfileInfo>, String> {
    let dir = match profiles_dir {
        Some(d) => PathBuf::from(d),
        None => super::common::profiles_dir(),
    };
    let entries = std::fs::read_dir(&dir).map_err(|_| {
        format!(
            "profiles directory not found: {} (run `configctl init`)",
            dir.display()
        )
    })?;
    let mut out = Vec::new();
    let mut names: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|c| c.path())).collect();
    names.sort();
    for path in names {
        let manifest = path.join("profile.toml");
        if !manifest.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&manifest)
            .map_err(|e| format!("read {}: {e:?}", manifest.display()))?;
        if text.len() > 1024 * 1024 {
            continue;
        }
        let profile = configctl_core::profile::Profile::from_toml(&text)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        out.push(ProfileInfo {
            name: profile.name.clone(),
            path,
            schema_version: profile.schema_version,
            description: profile.description.clone(),
        });
    }
    Ok(out)
}

/// Show the canonical rendering of a profile (validated first).
pub fn run_show(profile_arg: &str) -> Result<String, String> {
    let dir = super::common::resolve_profile_dir(profile_arg);
    let loaded = configctl_core::profile_load::load_profile_dir(&dir)?;
    let mut s = loaded.profile.to_toml()?;
    s.push_str("\n# --- secrets.manifest.toml ---\n");
    if let Some(m) = &loaded.manifest {
        s.push_str(&m.to_toml()?);
    }
    Ok(s)
}

/// Validate a profile; returns all errors (empty = valid).
pub fn run_validate(profile_arg: &str) -> Vec<String> {
    let dir = super::common::resolve_profile_dir(profile_arg);
    match configctl_core::profile_load::load_profile_dir(&dir) {
        Ok(_) => Vec::new(),
        Err(e) => e
            .trim_start_matches("profile validation failed:\n")
            .split("\n  - ")
            .map(|l| l.trim_start_matches("  - ").to_string())
            .collect(),
    }
}

/// Migrate a profile bundle to a target schema version.
pub fn run_migrate(profile_arg: &str, to: u32) -> Result<String, String> {
    if to != configctl_core::profile::SCHEMA_VERSION {
        return Err(format!(
            "unsupported target schema_version {to} (this build supports {})",
            configctl_core::profile::SCHEMA_VERSION
        ));
    }
    let dir = super::common::resolve_profile_dir(profile_arg);
    let loaded = configctl_core::profile_load::load_profile_dir(&dir)?;
    if loaded.profile.schema_version == to {
        return Ok(format!(
            "profile {:?} is already at schema_version {to}; no migration needed (no changes made)",
            loaded.identity
        ));
    }
    // Explicit one-way v1 → v2 migration; the bundle is rewritten only on
    // success (validate-after-migrate, fail-closed).
    let mut profile = loaded.profile.clone();
    let migrated = configctl_core::profile_migrate::migrate_to_v2(&mut profile)?;
    if !migrated {
        return Ok(format!(
            "profile {:?} is already at schema_version {to}; no migration needed (no changes made)",
            loaded.identity
        ));
    }
    profile.canonicalize();
    let errors = profile.validate();
    if !errors.is_empty() {
        return Err(format!("migrated profile invalid:\n  - {}", errors.join("\n  - ")));
    }
    let text = profile.to_toml()?;
    let target = dir.join("profile.toml");
    std::fs::write(&target, text).map_err(|e| format!("write {}: {e:?}", target.display()))?;
    Ok(format!(
        "profile {:?} migrated to schema_version {to} (v1 content preserved, v2 sections defaulted)",
        loaded.identity
    ))
}

/// Render `list` human output.
pub fn render_list_human(infos: &[ProfileInfo]) -> String {
    if infos.is_empty() {
        return "No profiles.\n".into();
    }
    let mut s = String::from("name\t\tpath\t\tschema\n\n");
    for i in infos {
        s.push_str(&format!(
            "{}\t\t{}\t\t{}\n",
            i.name,
            i.path.display(),
            i.schema_version
        ));
    }
    s
}
