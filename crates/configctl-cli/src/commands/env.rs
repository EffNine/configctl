//! `configctl env scan|list|verify` — first-class `.env` management.
//!
//! Read-only. Values are never rendered: `scan`/`list` show names,
//! classifications, and counts; `verify` checks schemas against discovered
//! variables and reports findings by name only.

use configctl_core::command::CommandRunner;
use configctl_core::profile_load::{self, LoadedProfile};
use configctl_core::secrets::{SecretBackend, SecretToolBackend};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// env scan / env list (discovery-backed)
// ---------------------------------------------------------------------------

/// Env-focused view over a scan result.
#[derive(Debug, Clone)]
pub struct EnvScanView {
    pub files: usize,
    pub variables: usize,
    pub secrets: usize,
    pub config_values: usize,
    /// (project, variable, classification) sorted.
    pub entries: Vec<(String, String, String)>,
}

/// Run an env scan over the given roots (read-only).
pub fn run_env_scan(
    roots: &[String],
    extra_roots: &[String],
    depth: Option<usize>,
    runner: &dyn CommandRunner,
) -> Result<EnvScanView, String> {
    let scan_out =
        crate::commands::scan::run_scan(roots, extra_roots, depth, false, false, false, runner);
    if let Some(err) = scan_out.error_envelope {
        return Err(err
            .errors
            .first()
            .map(|w| w.message.clone())
            .unwrap_or_default());
    }
    let result = scan_out.result;
    let mut entries = Vec::new();
    let mut secrets = 0usize;
    for e in &result.env_files {
        let project = e.project.clone().unwrap_or_else(|| "global".into());
        for c in &e.classifications {
            if c.classification == "secret" || c.classification == "likely_secret" {
                secrets += 1;
            }
            entries.push((project.clone(), c.name.clone(), c.classification.clone()));
        }
    }
    entries.sort();
    entries.dedup();
    let variables = entries.len();
    let config_values = variables.saturating_sub(secrets);
    Ok(EnvScanView {
        files: result.env_files.len(),
        variables,
        secrets,
        config_values,
        entries,
    })
}

/// Render human output for `env scan`.
pub fn render_scan_human(view: &EnvScanView) -> String {
    format!(
        "{} environment files found\n{} variables found\n{} likely secrets\n{} non-secret configuration values\n\nNo values were read into output.\n",
        view.files, view.variables, view.secrets, view.config_values
    )
}

/// Render human output for `env list`.
pub fn render_list_human(view: &EnvScanView, project_filter: Option<&str>) -> String {
    let mut s = String::from("project\t\tvariable\t\ttype\n\n");
    for (project, var, class) in &view.entries {
        if let Some(f) = project_filter {
            if project != f {
                continue;
            }
        }
        let kind = match class.as_str() {
            "secret" | "likely_secret" => "secret",
            _ => "config",
        };
        s.push_str(&format!("{project}\t\t{var}\t\t{kind}\n"));
    }
    s
}

// ---------------------------------------------------------------------------
// env verify (schema-backed)
// ---------------------------------------------------------------------------

/// One schema finding for output.
#[derive(Debug, Clone)]
pub struct EnvVerifyFinding {
    pub project: String,
    pub variable: String,
    pub kind: String,
    pub detail: String,
}

/// Result of `env verify`.
pub struct EnvVerifyOutput {
    pub findings: Vec<EnvVerifyFinding>,
    pub error: Option<String>,
    /// 0 clean, 3 errors, 2 usage.
    pub exit_code: i32,
}

/// Verify project env schemas in a profile bundle against live `.env` files.
/// Read-only. Exit 3 on missing/invalid/secret-ref findings; unknown
/// variables are warnings (exit 0 unless `--strict`).
pub fn run_env_verify(
    profile_arg: Option<&str>,
    project_filter: Option<&str>,
    strict: bool,
    home_override: Option<&Path>,
    runner: &dyn CommandRunner,
) -> EnvVerifyOutput {
    let profile_dir = match super::common::resolve_profile_default(profile_arg) {
        Ok(d) => d,
        Err(e) => {
            return EnvVerifyOutput {
                findings: Vec::new(),
                error: Some(e),
                exit_code: 2,
            };
        }
    };
    let loaded: LoadedProfile = match profile_load::load_profile_dir(&profile_dir) {
        Ok(l) => l,
        Err(e) => {
            return EnvVerifyOutput {
                findings: Vec::new(),
                error: Some(e),
                exit_code: 2,
            };
        }
    };
    let home: PathBuf = match home_override {
        Some(h) => h.to_path_buf(),
        None => match dirs::home_dir() {
            Some(h) => h,
            None => {
                return EnvVerifyOutput {
                    findings: Vec::new(),
                    error: Some("cannot determine $HOME".into()),
                    exit_code: 2,
                };
            }
        },
    };
    let manifest_refs: BTreeSet<String> = loaded
        .manifest
        .as_ref()
        .map(|m| m.secrets.iter().map(|s| s.secret_ref.clone()).collect())
        .unwrap_or_default();
    let backend = SecretToolBackend { runner };
    let mut findings = Vec::new();
    for project in &loaded.profile.projects {
        if let Some(f) = project_filter {
            if project.name != f {
                continue;
            }
        }
        let Some(schema_rel) = project.env_schema.as_deref() else {
            continue;
        };
        let Some(schema) = loaded.env_schemas.get(schema_rel) else {
            continue;
        };
        // Resolve the project dir (~/... against home; absolute accepted).
        let project_dir: PathBuf = if let Some(rest) = project.path.strip_prefix("~/") {
            home.join(rest)
        } else if project.path.starts_with('~') {
            continue;
        } else {
            PathBuf::from(&project.path)
        };
        let discovered = configctl_core::env_verify::read_project_env(&project_dir, 256 * 1024);
        let fs = configctl_core::env_verify::verify_project_schema(
            &project.name,
            schema,
            &discovered,
            &manifest_refs,
            &|r| backend.exists(r),
        );
        for f in fs {
            findings.push(EnvVerifyFinding {
                project: f.project,
                variable: f.variable,
                kind: match f.kind {
                    configctl_core::env_verify::EnvFindingKind::Missing => "missing",
                    configctl_core::env_verify::EnvFindingKind::Invalid => "invalid",
                    configctl_core::env_verify::EnvFindingKind::SecretRefMissing => {
                        "secret_ref_missing"
                    }
                    configctl_core::env_verify::EnvFindingKind::Unknown => "unknown",
                }
                .into(),
                detail: f.detail,
            });
        }
    }
    findings.sort_by(|a, b| (&a.project, &a.variable).cmp(&(&b.project, &b.variable)));
    let hard = findings.iter().any(|f| f.kind != "unknown");
    let soft = strict && !findings.is_empty();
    let exit_code = if hard || soft { 3 } else { 0 };
    EnvVerifyOutput {
        findings,
        error: None,
        exit_code,
    }
}

/// Render human output for `env verify`.
pub fn render_verify_human(out: &EnvVerifyOutput) -> String {
    if out.findings.is_empty() {
        return "Environment schemas: all projects PASS.\n".into();
    }
    let mut s = String::from("Environment schema findings:\n\n");
    for f in &out.findings {
        s.push_str(&format!(
            "  [{}] {}/{} — {}\n",
            f.kind, f.project, f.variable, f.detail
        ));
    }
    s
}
