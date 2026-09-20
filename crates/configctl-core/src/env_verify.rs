//! Project env-schema verification (P6).
//!
//! Compares discovered `.env` values against the bundle's `env/<project>.toml`
//! schemas. Reports missing/invalid/unknown variables and missing secret
//! references — without ever printing values. Read-only.

use crate::profile::EnvSchema;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// One schema finding.
#[derive(Debug, Clone)]
pub struct EnvFinding {
    pub project: String,
    pub variable: String,
    pub kind: EnvFindingKind,
    /// Redaction-safe detail (names only, never values).
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvFindingKind {
    /// Required variable absent from all env files.
    Missing,
    /// Present with the wrong type / enum violation.
    Invalid,
    /// Required secret with no manifest/backend reference.
    SecretRefMissing,
    /// In files but not in the schema (warning).
    Unknown,
}

/// Verify one project's discovered variables against its schema.
///
/// `discovered`: variable name → value (values used only for type checks,
/// never rendered). `manifest_refs`: secret refs known to the manifest.
pub fn verify_project_schema(
    project: &str,
    schema: &EnvSchema,
    discovered: &BTreeMap<String, String>,
    manifest_refs: &BTreeSet<String>,
    secret_exists: &dyn Fn(&str) -> Option<bool>,
) -> Vec<EnvFinding> {
    let mut out = Vec::new();
    let mut known: BTreeSet<&str> = BTreeSet::new();
    for var in &schema.variables {
        known.insert(var.name.as_str());
        match discovered.get(&var.name) {
            None => {
                if var.required {
                    out.push(EnvFinding {
                        project: project.into(),
                        variable: var.name.clone(),
                        kind: EnvFindingKind::Missing,
                        detail: "required variable absent".into(),
                    });
                }
            }
            Some(value) => {
                if !type_ok(&var.var_type, var.values.as_deref(), value) {
                    out.push(EnvFinding {
                        project: project.into(),
                        variable: var.name.clone(),
                        kind: EnvFindingKind::Invalid,
                        detail: format!("value does not satisfy type {:?}", var.var_type),
                    });
                }
                if var.secret && var.required {
                    // The variable must have a manifest entry (name-keyed).
                    let has_manifest = manifest_refs
                        .iter()
                        .any(|r| r.rsplit('/').next().map(|n| n == var.name).unwrap_or(false));
                    if !has_manifest {
                        out.push(EnvFinding {
                            project: project.into(),
                            variable: var.name.clone(),
                            kind: EnvFindingKind::SecretRefMissing,
                            detail: "required secret has no manifest reference".into(),
                        });
                    } else {
                        // Existence probe for the matching ref(s).
                        let mut any_present = false;
                        let mut any_unknown = false;
                        for r in manifest_refs {
                            if r.rsplit('/').next().map(|n| n == var.name).unwrap_or(false) {
                                match secret_exists(r) {
                                    Some(true) => any_present = true,
                                    None => any_unknown = true,
                                    _ => {}
                                }
                            }
                        }
                        if !any_present && !any_unknown {
                            out.push(EnvFinding {
                                project: project.into(),
                                variable: var.name.clone(),
                                kind: EnvFindingKind::SecretRefMissing,
                                detail: "secret reference missing in backend".into(),
                            });
                        }
                    }
                }
            }
        }
    }
    for name in discovered.keys() {
        if !known.contains(name.as_str()) {
            out.push(EnvFinding {
                project: project.into(),
                variable: name.clone(),
                kind: EnvFindingKind::Unknown,
                detail: "variable not declared in schema".into(),
            });
        }
    }
    out.sort_by(|a, b| (&a.project, &a.variable).cmp(&(&b.project, &b.variable)));
    out
}

/// Type check for a discovered value (never rendered).
fn type_ok(var_type: &str, allowed: Option<&[String]>, value: &str) -> bool {
    let v = value.trim();
    match var_type {
        "string" => true,
        "integer" => v.parse::<i64>().is_ok(),
        "boolean" => matches!(
            v.to_lowercase().as_str(),
            "true" | "false" | "0" | "1" | "yes" | "no" | "on" | "off"
        ),
        "enum" => allowed.map(|a| a.iter().any(|x| x == v)).unwrap_or(false),
        _ => false,
    }
}

/// Default `.env*` basenames discovered per project root (P0 §4.2).
pub const ENV_BASENAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.test",
    ".env.production",
    ".env.example",
    ".env.sample",
];

/// Read all discoverable env files under a project dir (bounded, in-memory).
/// Returns variable name → first-seen value.
pub fn read_project_env(project_dir: &Path, max_bytes: usize) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for base in ENV_BASENAMES {
        let p = project_dir.join(base);
        let Ok(meta) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let Ok(parsed) = crate::envfile::parse_file(
            &p,
            &crate::envfile::ParseLimits {
                max_bytes,
                max_variables: 10_000,
            },
        ) else {
            continue;
        };
        for v in &parsed.variables {
            v.with_value(|val| {
                map.entry(v.name.clone()).or_insert_with(|| val.to_string());
            });
        }
    }
    map
}
