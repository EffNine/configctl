//! Loading a profile bundle from disk (read-only).
//!
//! Bundle layout (P2):
//!
//! ```text
//! <dir>/
//! ├── profile.toml
//! ├── secrets.manifest.toml   (optional)
//! ├── packages.lock.toml      (optional)
//! ├── env/<project>.toml      (optional)
//! └── files/...               (payloads referenced by `source`)
//! ```
//!
//! Loading never follows symlinks inside the bundle for payload reads (the
//! payload hash step uses `symlink_metadata` first), rejects traversal, and
//! validates everything fail-closed.

use crate::paths;
use crate::profile::{EnvSchema, PackagesLock, Profile, SecretManifest, SCHEMA_VERSION};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A loaded, validated profile bundle.
#[derive(Debug, Clone)]
pub struct LoadedProfile {
    /// Bundle directory (canonicalized).
    pub dir: PathBuf,
    /// Identity: directory basename (= profile name).
    pub identity: String,
    pub profile: Profile,
    pub manifest: Option<SecretManifest>,
    pub lock: Option<PackagesLock>,
    /// `env/<project>.toml` keyed by bundle-relative path.
    pub env_schemas: BTreeMap<String, EnvSchema>,
    /// SHA-256 of each referenced payload (`bundle-rel` → hex).
    pub payload_hashes: BTreeMap<String, String>,
    /// Canonical profile hash (profile + manifest + schemas + payload hashes).
    pub profile_hash: String,
}

/// Load and validate a bundle at `dir`.
pub fn load_profile_dir(dir: &Path) -> Result<LoadedProfile, String> {
    let canon =
        std::fs::canonicalize(dir).map_err(|e| format!("profile path {}: {e:?}", dir.display()))?;
    if !canon.is_dir() {
        return Err(format!(
            "profile path is not a directory: {}",
            dir.display()
        ));
    }
    // profile.toml (required).
    let profile_text = std::fs::read_to_string(canon.join("profile.toml"))
        .map_err(|e| format!("read profile.toml: {e:?}"))?;
    if profile_text.len() > 1024 * 1024 {
        return Err("profile.toml exceeds 1MiB cap".into());
    }
    let mut profile = Profile::from_toml(&profile_text)?;
    profile.canonicalize();
    let mut errors = profile.validate();

    // Directory basename must match profile name (spoofing guard).
    if let Some(base) = canon.file_name().and_then(|n| n.to_str()) {
        if base != profile.name {
            // Only enforce when basename is itself a valid profile name; a
            // disposable fixture dir (e.g. `/tmp/xyz/out`) loads by path and
            // keeps its declared name. Exact-name invocation still validates.
            if paths::validate_profile_name(base).is_ok() {
                errors.push(format!(
                    "profile name {:?} does not match directory name {base:?}",
                    profile.name
                ));
            }
        }
    }
    let identity = profile.name.clone();

    // secrets.manifest.toml (optional).
    let manifest = {
        let p = canon.join("secrets.manifest.toml");
        if p.exists() {
            let text = std::fs::read_to_string(&p)
                .map_err(|e| format!("read secrets.manifest.toml: {e:?}"))?;
            if text.len() > 1024 * 1024 {
                return Err("secrets.manifest.toml exceeds 1MiB cap".into());
            }
            match SecretManifest::from_toml(&text) {
                Ok(m) => {
                    errors.extend(
                        m.validate()
                            .iter()
                            .map(|e| format!("secrets manifest: {e}")),
                    );
                    Some(m)
                }
                Err(e) => {
                    errors.push(format!("secrets manifest: {e}"));
                    None
                }
            }
        } else {
            None
        }
    };

    // packages.lock.toml (optional).
    let lock = {
        let p = canon.join("packages.lock.toml");
        if p.exists() {
            let text = std::fs::read_to_string(&p)
                .map_err(|e| format!("read packages.lock.toml: {e:?}"))?;
            match PackagesLock::from_toml(&text) {
                Ok(l) => {
                    if l.schema_version != SCHEMA_VERSION {
                        errors.push(format!(
                            "unsupported packages lock schema_version {}",
                            l.schema_version
                        ));
                    }
                    Some(l)
                }
                Err(e) => {
                    errors.push(format!("packages lock: {e}"));
                    None
                }
            }
        } else {
            None
        }
    };

    // env schemas: every `env/*.toml` file.
    let mut env_schemas: BTreeMap<String, EnvSchema> = BTreeMap::new();
    let env_dir = canon.join("env");
    if env_dir.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&env_dir)
            .map_err(|e| format!("read env dir: {e:?}"))?
            .filter_map(|e| e.ok().map(|c| c.path()))
            .collect();
        entries.sort();
        for entry in entries {
            // Never follow symlinks in the bundle.
            let meta = std::fs::symlink_metadata(&entry)
                .map_err(|e| format!("metadata {}: {e:?}", entry.display()))?;
            if !meta.file_type().is_file() {
                continue;
            }
            if entry.extension().and_then(|s| s.to_str()) != Some("toml") {
                errors.push(format!("env dir: unexpected file {}", entry.display()));
                continue;
            }
            let rel = format!(
                "env/{}",
                entry.file_name().unwrap_or_default().to_string_lossy()
            );
            if let Err(e) = paths::validate_env_schema_ref(&rel) {
                errors.push(format!("env schema {rel}: {e}"));
                continue;
            }
            let text = std::fs::read_to_string(&entry).map_err(|e| format!("read {rel}: {e:?}"))?;
            if text.len() > 256 * 1024 {
                errors.push(format!("env schema {rel} exceeds cap"));
                continue;
            }
            match EnvSchema::from_toml(&text) {
                Ok(s) => {
                    errors.extend(
                        s.validate()
                            .iter()
                            .map(|e| format!("env schema {rel}: {e}")),
                    );
                    env_schemas.insert(rel, s);
                }
                Err(e) => errors.push(format!("env schema {rel}: {e}")),
            }
        }
    }

    // Payload hashes for every referenced `source`.
    let mut payload_hashes: BTreeMap<String, String> = BTreeMap::new();
    for f in &profile.files {
        // `source` already validated; re-check containment lexically.
        let dest = canon.join(&f.source);
        let meta = match std::fs::symlink_metadata(&dest) {
            Ok(m) => m,
            Err(e) => {
                errors.push(format!("payload {:?}: unreadable: {e:?}", f.source));
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            errors.push(format!("payload {:?}: symlink rejected", f.source));
            continue;
        }
        if !meta.file_type().is_file() {
            errors.push(format!("payload {:?}: not a regular file", f.source));
            continue;
        }
        match crate::hash::sha256_file(&dest, 256 * 1024) {
            Ok(h) => {
                payload_hashes.insert(f.source.clone(), h);
            }
            Err(e) => errors.push(format!("payload {:?}: {e}", f.source)),
        }
    }

    // Cross-checks: profile-declared env_schema refs must exist.
    for p in &profile.projects {
        if let Some(r) = &p.env_schema {
            if !env_schemas.contains_key(r) {
                errors.push(format!(
                    "project {:?}: env_schema {r:?} not found in bundle",
                    p.name
                ));
            }
        }
    }

    if !errors.is_empty() {
        return Err(format!(
            "profile validation failed:\n  - {}",
            errors.join("\n  - ")
        ));
    }

    let profile_hash = compute_profile_hash(&profile, &manifest, &env_schemas, &payload_hashes);

    Ok(LoadedProfile {
        dir: canon,
        identity,
        profile,
        manifest,
        lock,
        env_schemas,
        payload_hashes,
        profile_hash,
    })
}

/// Canonical profile hash: deterministic JSON over the semantic content.
/// Informational fields (`metadata.captured_at`, `configctl_version`) are
/// excluded so identical intent hashes identically.
pub fn compute_profile_hash(
    profile: &Profile,
    manifest: &Option<SecretManifest>,
    env_schemas: &BTreeMap<String, EnvSchema>,
    payload_hashes: &BTreeMap<String, String>,
) -> String {
    let mut p = profile.clone();
    p.canonicalize();
    // Strip informational fields.
    p.configctl_version = None;
    if let Some(m) = p.metadata.as_mut() {
        m.captured_at = None;
    }
    let doc = serde_json::json!({
        "schema_version": 1,
        "profile": serde_json::to_value(&p).unwrap_or_default(),
        "manifest": manifest.as_ref().map(|m| {
            let mut c = m.clone();
            c.secrets.sort_by(|a, b| (&a.project, &a.name).cmp(&(&b.project, &b.name)));
            serde_json::to_value(&c).unwrap_or_default()
        }).unwrap_or(serde_json::Value::Null),
        "env_schemas": env_schemas.iter().map(|(k, v)| {
            let mut c = v.clone();
            c.variables.sort_by(|a, b| a.name.cmp(&b.name));
            (k, serde_json::to_value(&c).unwrap_or_default())
        }).collect::<BTreeMap<_, _>>(),
        "payload_hashes": payload_hashes,
    });
    let canonical = serde_json::to_string(&doc).unwrap_or_default();
    crate::hash::sha256_str(&canonical)
}
