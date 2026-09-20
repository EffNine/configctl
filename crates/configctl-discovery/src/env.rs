//! `.env` file discovery and per-file metadata.

use configctl_core::envfile::{self};
use configctl_core::limits::Limits;
use std::path::Path;

/// Whether a file name is a recognized `.env` variant.
///
/// Recognized: `.env`, `.env.local`, `.env.development`, `.env.test`,
/// `.env.production`, `.env.example`, `.env.sample`, and any
/// `.env.<layer>` / `<name>.env` where the layer matches
/// `[a-z0-9_-]+`.
pub fn is_env_filename(name: &str) -> bool {
    if name == ".env" {
        return true;
    }
    // `.env.<layer>`
    if let Some(rest) = name.strip_prefix(".env.") {
        return !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    }
    // `<name>.env` (a dotfile whose name ends in `.env`, e.g. `db.env`)
    if let Some(stem) = name.strip_suffix(".env") {
        return !stem.is_empty()
            && stem.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' || c == '.'
            });
    }
    false
}

/// The layer name of a `.env` file (`None` for plain `.env`).
pub fn env_layer(name: &str) -> Option<String> {
    if name == ".env" {
        None
    } else {
        name.strip_prefix(".env.").map(|r| r.to_string())
    }
}

/// Metadata + parse result for one discovered `.env` file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnvFileRecord {
    pub path: String,
    pub project: Option<String>,
    pub relative: Option<String>,
    pub size: u64,
    pub permissions: Option<u32>,
    pub owner: Option<u32>,
    pub variable_names: Vec<String>,
    pub variable_count: usize,
    pub classifications: Vec<VariableClassification>,
    pub secret_count: usize,
    pub likely_secret_count: usize,
    pub tracked_by_git: GitStatus,
    pub malformed_count: usize,
    pub warnings: Vec<String>,
}

/// Per-variable classification (redaction-safe: names only, never values).
#[derive(Debug, Clone, serde::Serialize)]
pub struct VariableClassification {
    pub name: String,
    pub classification: String,
    pub signals: Vec<String>,
}

/// Git tracking status for a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GitStatus {
    #[default]
    Unknown,
    Tracked,
    Untracked,
    Ignored,
}

impl GitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            GitStatus::Tracked => "tracked",
            GitStatus::Untracked => "untracked",
            GitStatus::Ignored => "ignored",
            GitStatus::Unknown => "unknown",
        }
    }
}

/// Parse + classify one `.env` file under the configured limits, registering
/// detected secret values into `registry` so they are redacted at every sink.
pub fn process_env_file(
    path: &Path,
    limits: &Limits,
    git_status: GitStatus,
    registry: &configctl_core::redact::SecretRegistry,
) -> Result<EnvFileRecord, String> {
    use crate::secret::{classify_variable, EntropyScorer};

    let meta = std::fs::metadata(path).map_err(|e| format!("metadata: {e:?}"))?;
    let size = meta.len();
    if size > limits.max_file_bytes as u64 {
        return Ok(EnvFileRecord {
            path: path.to_string_lossy().into_owned(),
            project: None,
            relative: None,
            size,
            permissions: metadata_perm(&meta),
            owner: metadata_owner(&meta),
            variable_names: Vec::new(),
            variable_count: 0,
            classifications: Vec::new(),
            secret_count: 0,
            likely_secret_count: 0,
            tracked_by_git: git_status,
            malformed_count: 0,
            warnings: vec![format!("file exceeds {size}-byte cap; not parsed")],
        });
    }

    let parsed = envfile::parse_file(
        path,
        &envfile::ParseLimits {
            max_bytes: limits.max_file_bytes,
            max_variables: limits.max_findings,
        },
    )
    .map_err(|e| e.to_string())?;

    let scorer = EntropyScorer::default();
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut classifications = Vec::new();
    let mut secret_count = 0usize;
    let mut likely_secret_count = 0usize;
    for var in &parsed.variables {
        let res = classify_variable(var, &stem, &scorer);
        if matches!(res.classification, crate::secret::Classification::Secret) {
            secret_count += 1;
            // Register the value so it is redacted at every sink.
            var.with_value(|v| registry.register(v));
        }
        if matches!(
            res.classification,
            crate::secret::Classification::LikelySecret
        ) {
            likely_secret_count += 1;
            var.with_value(|v| registry.register(v));
        }
        classifications.push(VariableClassification {
            name: var.name.clone(),
            classification: res.classification.as_str().to_string(),
            signals: res.signals,
        });
    }

    // Register detected secret-like values for redaction is done by the
    // scanner (which has registry access); here we only classify.

    let variable_names = envfile::variable_names(&parsed);
    let warnings = parsed
        .malformed
        .iter()
        .take(10)
        .map(|(line, kind)| format!("line {line}: {kind}"))
        .collect();

    Ok(EnvFileRecord {
        path: path.to_string_lossy().into_owned(),
        project: None,
        relative: None,
        size,
        permissions: metadata_perm(&meta),
        owner: metadata_owner(&meta),
        variable_names,
        variable_count: parsed.variables.len(),
        classifications,
        secret_count,
        likely_secret_count,
        tracked_by_git: git_status,
        malformed_count: parsed.malformed.len(),
        warnings,
    })
}

#[cfg(unix)]
fn metadata_perm(meta: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn metadata_perm(_meta: &std::fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
fn metadata_owner(meta: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(meta.uid())
}

#[cfg(not(unix))]
fn metadata_owner(_meta: &std::fs::Metadata) -> Option<u32> {
    None
}

// Re-export for scanner use.
