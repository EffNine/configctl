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

// ---------------------------------------------------------------------------
// env explain (v1.2 E1 — read-only environment source map)
// ---------------------------------------------------------------------------

use configctl_core::envmap::{self, EnvSourceMap, LineClass, SourceKind};

/// Result of `env explain`.
pub struct EnvExplainOutput {
    pub text: String,
    pub data: serde_json::Value,
    pub error: Option<String>,
    pub exit_code: i32,
}

/// Fixed, documented read order for the known shell-startup sources. Lower
/// values are read earlier in a session, so higher values win.
fn fixed_sources() -> [(SourceKind, u32); 6] {
    [
        (SourceKind::Bashrc, 1),
        (SourceKind::BashProfile, 2),
        (SourceKind::Profile, 3),
        (SourceKind::Zshrc, 4),
        (SourceKind::Zshenv, 5),
        (SourceKind::Xprofile, 6),
    ]
}

fn read_bounded(path: &Path) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(envmap::MAX_SOURCE_BYTES as u64)
        .read_to_end(&mut buf)
        .ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Build the read-only source map for `$HOME` (or `home_override`).
pub fn build_env_source_map(home: &Path) -> EnvSourceMap {
    let mut sources = Vec::new();
    for (kind, order) in fixed_sources() {
        let Some(rel) = kind.rel_path() else { continue };
        let abs = home.join(rel);
        if !abs.is_file() {
            continue;
        }
        if let Some(content) = read_bounded(&abs) {
            sources.push(envmap::parse_source(
                &format!("~/{rel}"),
                &content,
                kind,
                order,
            ));
        }
    }

    // systemd user environment files (desktop apps / user services).
    let envd = home.join(".config/environment.d");
    if let Ok(entries) = std::fs::read_dir(&envd) {
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|x| x == "conf").unwrap_or(false))
            .collect();
        files.sort();
        for (i, p) in files.iter().enumerate() {
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if let Some(content) = read_bounded(p) {
                    sources.push(envmap::parse_source(
                        &format!("~/.config/environment.d/{name}"),
                        &content,
                        SourceKind::EnvironmentD,
                        7 + i as u32,
                    ));
                }
            }
        }
    }

    EnvSourceMap { sources }
}

/// Run `env explain`: report where environment declarations live, which value
/// wins today, and what could be consolidated. Never modifies anything.
pub fn run_env_explain(home_override: Option<&Path>) -> EnvExplainOutput {
    let home: PathBuf = match home_override {
        Some(h) => h.to_path_buf(),
        None => match dirs::home_dir() {
            Some(h) => h,
            None => {
                return EnvExplainOutput {
                    text: String::new(),
                    data: serde_json::json!({}),
                    error: Some("cannot determine $HOME".into()),
                    exit_code: 2,
                }
            }
        },
    };

    let map = build_env_source_map(&home);
    let effective = map.effective();
    let conflicts = map.conflicts();
    let secret_names = map.secret_names();
    let managed: Vec<&str> = {
        let mut v: Vec<&str> = map
            .sources
            .iter()
            .flat_map(|s| s.declarations.iter())
            .filter(|d| d.class == LineClass::Managed)
            .map(|d| d.name.as_str())
            .collect();
        v.sort();
        v.dedup();
        v
    };

    // ---- human output ----
    let mut text = String::new();
    if map.sources.is_empty() {
        text.push_str(
            "No shell startup files were found under $HOME.\n\
             Add settings to ~/.bashrc (or ~/.zshrc) and re-run `configctl env explain`.\n",
        );
    } else {
        text.push_str(&format!(
            "Your shell settings live in {} file(s).\n\n",
            map.sources.len()
        ));
        for src in &map.sources {
            text.push_str(&format!("  {} ({})\n", src.path, src.kind.read_when()));
            for d in &src.declarations {
                match d.class {
                    LineClass::Managed => {
                        let wins = effective
                            .get(&d.name)
                            .map(|(v, p)| v == d.value.as_deref().unwrap_or("") && p == &src.path)
                            .unwrap_or(false);
                        let note = if wins { "currently wins" } else { "overridden" };
                        text.push_str(&format!(
                            "    line {:<5} {}={:<24} {}\n",
                            d.line,
                            d.name,
                            d.value.as_deref().unwrap_or(""),
                            note
                        ));
                    }
                    LineClass::Special => text.push_str(&format!(
                        "    line {:<5} {}  left alone ({})\n",
                        d.line,
                        d.name,
                        d.reason.as_deref().unwrap_or("behaviour-defining")
                    )),
                    LineClass::Secret => text.push_str(&format!(
                        "    line {:<5} {}  looks like a secret — managed by reference\n",
                        d.line, d.name
                    )),
                    LineClass::Structure => text.push_str(&format!(
                        "    line {:<5} {}  (structure, not a setting)\n",
                        d.line, d.name
                    )),
                    LineClass::Manual => text.push_str(&format!(
                        "    line {:<5} {}  left alone ({})\n",
                        d.line,
                        d.name,
                        d.reason.as_deref().unwrap_or("conditional")
                    )),
                }
            }
            text.push('\n');
        }
        if !conflicts.is_empty() {
            text.push_str("Conflicts (same variable, different values):\n");
            for c in &conflicts {
                text.push_str(&format!(
                    "  {} is set to \"{}\" in {} but \"{}\" in {}\n",
                    c.name, c.shadowed_value, c.shadowed, c.winner_value, c.winner
                ));
            }
            text.push('\n');
        }
        text.push_str(&format!(
            "{} setting(s) could be consolidated into one managed file\n\
             (~/.config/configctl/env.sh); {} look like secrets and stay referenced.\n",
            managed.len(),
            secret_names.len()
        ));
        text.push_str("Nothing has been changed. This command is read-only.\n");
    }

    // ---- JSON output ----
    let decl_json: Vec<serde_json::Value> = map
        .sources
        .iter()
        .flat_map(|s| {
            s.declarations.iter().map(move |d| {
                serde_json::json!({
                    "source": s.path,
                    "name": d.name,
                    "line": d.line,
                    "classification": d.class.as_str(),
                    "reason": d.reason,
                    "value": d.value,
                    "secret": d.secret,
                })
            })
        })
        .collect();
    let precedence: Vec<serde_json::Value> = effective
        .iter()
        .map(|(k, (v, src))| serde_json::json!({"name": k, "value": v, "source": src}))
        .collect();
    let data = serde_json::json!({
        "sources": map.sources.iter().map(|s| serde_json::json!({
            "path": s.path,
            "kind": format!("{:?}", s.kind).to_lowercase(),
            "family": format!("{:?}", s.family).to_lowercase(),
            "read_order": s.read_order,
            "declarations": s.declarations.iter().map(|d| serde_json::json!({
                "name": d.name, "line": d.line,
                "classification": d.class.as_str(),
                "reason": d.reason, "value": d.value, "secret": d.secret,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "declarations": decl_json,
        "conflicts": conflicts.iter().map(|c| serde_json::json!({
            "name": c.name, "winner": c.winner, "winner_value": c.winner_value,
            "shadowed": c.shadowed, "shadowed_value": c.shadowed_value,
        })).collect::<Vec<_>>(),
        "precedence": precedence,
        "secret_names": secret_names,
        "managed_count": managed.len(),
    });

    EnvExplainOutput {
        text,
        data,
        error: None,
        exit_code: 0,
    }
}

// ---------------------------------------------------------------------------
// env consolidate (v1.2 — preview only until the write engine, phase E2)
// ---------------------------------------------------------------------------

/// Result of `env consolidate`.
pub struct EnvConsolidateOutput {
    pub text: String,
    pub data: serde_json::Value,
    pub error: Option<String>,
    pub exit_code: i32,
}

fn consolidate_err(msg: &str, exit_code: i32) -> EnvConsolidateOutput {
    EnvConsolidateOutput {
        text: String::new(),
        data: serde_json::json!({}),
        error: Some(msg.to_string()),
        exit_code,
    }
}

/// Plan (and, for now, only preview) consolidation of environment settings
/// into the canonical managed file plus per-rc include blocks.
///
/// The write path is phase E2 in `docs/ENV_CONSOLIDATION.md`: it must go
/// through the plan → hash-bound approval → journal → backup → rollback
/// engine, which is not wired for these op kinds yet. This command therefore
/// performs no writes; without `--dry-run` it reports the unimplemented
/// milestone rather than mutating anything.
pub fn run_env_consolidate(
    vars: &[String],
    mode: &str,
    dry_run: bool,
    home_override: Option<&Path>,
) -> EnvConsolidateOutput {
    if mode == "move" {
        return consolidate_err(
            "env consolidate --mode move is assistance-only and not implemented until phase E5",
            2,
        );
    }
    if mode != "include" {
        return consolidate_err("--mode must be 'include' (or 'move')", 2);
    }
    if !dry_run {
        return consolidate_err(
            "env consolidate writes are not implemented until phase E2; re-run with --dry-run to preview",
            2,
        );
    }

    let home: PathBuf = match home_override {
        Some(h) => h.to_path_buf(),
        None => match dirs::home_dir() {
            Some(h) => h,
            None => return consolidate_err("cannot determine $HOME", 2),
        },
    };

    let map = build_env_source_map(&home);
    let effective = map.effective();

    for v in vars {
        if !effective.contains_key(v) {
            return consolidate_err(
                &format!("variable {v} is not a consolidatable setting (no managed value found)"),
                2,
            );
        }
    }

    let selected: Vec<(String, String)> = if vars.is_empty() {
        effective
            .iter()
            .map(|(k, (v, _))| (k.clone(), v.clone()))
            .collect()
    } else {
        vars.iter()
            .filter_map(|v| effective.get(v).map(|(val, _)| (v.clone(), val.clone())))
            .collect()
    };

    // §6.3: two unmanaged sources with different values require --var selection.
    let conflicts = map.conflicts();
    let unresolved: Vec<String> = conflicts
        .iter()
        .filter(|c| selected.iter().any(|(k, _)| k == &c.name))
        .map(|c| c.name.clone())
        .collect();
    if !unresolved.is_empty() && vars.is_empty() {
        return consolidate_err(
            &format!(
                "conflicting variables need an explicit choice with --var: {}",
                unresolved.join(", ")
            ),
            5,
        );
    }

    // Compose the canonical file and the include-block list.
    let canonical = envmap::canonical_env_file(&selected);
    let selected_names: BTreeSet<&str> = selected.iter().map(|(k, _)| k.as_str()).collect();
    let mut include_targets: Vec<String> = Vec::new();
    for src in &map.sources {
        if !src.kind.participates_default() || src.kind == SourceKind::EnvironmentD {
            continue;
        }
        let declares_selected = src
            .declarations
            .iter()
            .any(|d| d.class == LineClass::Managed && selected_names.contains(d.name.as_str()));
        if declares_selected {
            include_targets.push(src.path.clone());
        }
    }

    // Shadowing report: managed values still declared in unmanaged sources.
    let mut shadowed: Vec<String> = Vec::new();
    for src in &map.sources {
        for d in &src.declarations {
            if d.class == LineClass::Managed && selected_names.contains(d.name.as_str()) {
                shadowed.push(format!(
                    "{}:{} {}={} (now overridden by the managed value)",
                    src.path,
                    d.line,
                    d.name,
                    d.value.as_deref().unwrap_or("")
                ));
            }
        }
    }

    let canonical_path = format!("~/{}", envmap::CANONICAL_REL);
    let block = envmap::include_block();

    let mut text = String::new();
    text.push_str("Dry run — nothing will be written.\n\n");
    text.push_str(&format!("Canonical file {canonical_path}:\n"));
    for line in canonical.lines() {
        text.push_str(&format!("  {line}\n"));
    }
    if include_targets.is_empty() {
        text.push_str(
            "\nNo existing shell file declares a selected variable; no include block is needed.\n",
        );
    } else {
        for target in &include_targets {
            text.push_str(&format!("\nInclude block appended to {target}:\n"));
            for line in block.lines() {
                text.push_str(&format!("  {line}\n"));
            }
        }
    }
    if !shadowed.is_empty() {
        text.push_str("\nShadowing after consolidation:\n");
        for s in &shadowed {
            text.push_str(&format!("  {s}\n"));
        }
    }
    text.push_str(
        "\nNot applied: the journaled write engine is phase E2 \
         (docs/ENV_CONSOLIDATION.md §13). Nothing has been changed.\n",
    );

    let data = serde_json::json!({
        "dry_run": true,
        "mode": mode,
        "canonical_path": canonical_path,
        "canonical_content": canonical,
        "include_block": block,
        "include_targets": include_targets,
        "shadowed": shadowed,
        "selected": selected.iter().map(|(k, v)| serde_json::json!({"name": k, "value": v})).collect::<Vec<_>>(),
    });

    EnvConsolidateOutput {
        text,
        data,
        error: None,
        exit_code: 0,
    }
}
