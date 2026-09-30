//! `configctl env scan|list|verify` — first-class `.env` management.
//!
//! Read-only. Values are never rendered: `scan`/`list` show names,
//! classifications, and counts; `verify` checks schemas against discovered
//! variables and reports findings by name only.

use configctl_core::command::CommandRunner;
use configctl_core::profile_load::{self, LoadedProfile};
use configctl_core::secrets::{SecretBackend, SecretToolBackend};
use std::collections::{BTreeMap, BTreeSet};
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

/// Everything the consolidation plan needs, computed once so the preview and
/// the plan describe exactly the same change.
struct ConsolidationInputs {
    rc_targets: Vec<configctl_core::plan::RcTarget>,
    canonical_current: Option<Vec<u8>>,
    envd_current: Option<BTreeMap<String, String>>,
    warnings: Vec<configctl_core::plan::PlanWarning>,
    /// Human lines for the shadowing report (names and locations only).
    shadowed: Vec<String>,
}

fn consolidation_inputs(home: &Path, loaded: &LoadedProfile) -> ConsolidationInputs {
    let names: BTreeSet<String> = configctl_core::plan::canonical_env_entries(loaded)
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    let map = build_env_source_map(home);

    let mut rc_targets: Vec<configctl_core::plan::RcTarget> = Vec::new();
    let mut warnings: Vec<configctl_core::plan::PlanWarning> = Vec::new();
    let mut shadowed: Vec<String> = Vec::new();

    for src in &map.sources {
        // Only shell startup files participate; environment.d already exists
        // for the session/services side and is written by the normal apply
        // path from the same profile data.
        if !src.kind.participates_default() || src.kind == SourceKind::EnvironmentD {
            continue;
        }
        let declares_selected = src
            .declarations
            .iter()
            .any(|d| d.class == LineClass::Managed && names.contains(d.name.as_str()));
        for d in &src.declarations {
            if d.class == LineClass::Managed && names.contains(d.name.as_str()) {
                shadowed.push(format!("{}:{} {}", src.path, d.line, d.name));
                warnings.push(configctl_core::plan::PlanWarning {
                    code: "shadowed_declaration".into(),
                    message: format!(
                        "{}:{} {} is still declared here; the managed block overrides it in this file",
                        src.path, d.line, d.name
                    ),
                });
            }
        }
        if !declares_selected {
            continue;
        }
        let Some(rel) = src.kind.rel_path() else {
            continue;
        };
        let abs = home.join(rel);
        let current = std::fs::read(&abs).ok();
        rc_targets.push(configctl_core::plan::RcTarget {
            target: format!("~/{rel}"),
            current,
        });
    }

    let canonical_current = std::fs::read(home.join(envmap::CANONICAL_REL)).ok();
    // Current session/services artifact (written by the normal apply path).
    let envd_current = std::fs::read(home.join(configctl_core::apply::MANAGED_ENV_REL))
        .ok()
        .and_then(|b| configctl_core::apply::parse_env_bytes(&b));
    ConsolidationInputs {
        rc_targets,
        canonical_current,
        envd_current,
        warnings,
        shadowed,
    }
}

/// `env consolidate` — turn the profile's `[environment]` literals into a
/// journaled plan that writes the canonical managed shell env file plus one
/// marker include block per participating rc file.
///
/// With `--dry-run` it prints the exact change and writes nothing (not even a
/// plan). Otherwise it persists a plan and stops there: the mutation happens
/// only through `configctl apply`, with the usual approval, journal, backup,
/// and rollback guarantees.
#[allow(clippy::too_many_arguments)]
pub fn run_env_consolidate(
    profile_arg: Option<&str>,
    state_dir_arg: Option<&str>,
    home_override: Option<&Path>,
    dry_run: bool,
    mode: &str,
) -> EnvConsolidateOutput {
    if mode == "move" {
        return consolidate_err(
            "env consolidate --mode move is assisted-manual only: nothing was changed. \
             Re-run with --dry-run to preview the tombstone patch, or \
             --emit-patch <file> to write it (with timestamped backups). \
             There is no automatic apply path for move mode.",
            2,
        );
    }
    if mode != "include" {
        return consolidate_err("--mode must be 'include' (or 'move')", 2);
    }

    let profile_dir = match super::common::resolve_profile_default(profile_arg) {
        Ok(d) => d,
        Err(e) => return consolidate_err(&e, 2),
    };
    let loaded: LoadedProfile = match profile_load::load_profile_dir(&profile_dir) {
        Ok(l) => l,
        Err(e) => return consolidate_err(&e, 2),
    };

    let home: PathBuf = match home_override {
        Some(h) => h.to_path_buf(),
        None => match dirs::home_dir() {
            Some(h) => h,
            None => return consolidate_err("cannot determine $HOME", 2),
        },
    };

    let inputs = consolidation_inputs(&home, &loaded);
    let entries = configctl_core::plan::canonical_env_entries(&loaded);

    if dry_run {
        let canonical = envmap::canonical_env_file(&entries);
        let block = envmap::include_block();
        let mut text = String::new();
        text.push_str("Dry run — nothing will be written.\n\n");
        text.push_str(&format!("Canonical file ~/{}:\n", envmap::CANONICAL_REL));
        for line in canonical.lines() {
            text.push_str(&format!("  {line}\n"));
        }
        if inputs.rc_targets.is_empty() {
            text.push_str(
                "\nNo shell startup file declares a managed setting; no include block is needed.\n",
            );
        } else {
            for rc in &inputs.rc_targets {
                text.push_str(&format!("\nInclude block appended to {}:\n", rc.target));
                for line in block.lines() {
                    text.push_str(&format!("  {line}\n"));
                }
            }
        }
        if !inputs.shadowed.is_empty() {
            text.push_str("\nShadowing after consolidation:\n");
            for s in &inputs.shadowed {
                text.push_str(&format!("  {s} (overridden by the managed value)\n"));
            }
        }
        text.push_str(
            "\nNothing has been changed. Drop --dry-run to persist a plan, then\n\
             `configctl apply --last` to apply it (approval, journal, backup, rollback).\n",
        );
        let data = serde_json::json!({
            "dry_run": true,
            "mode": mode,
            "canonical_path": format!("~/{}", envmap::CANONICAL_REL),
            "canonical_content": canonical,
            "include_block": block,
            "include_targets": inputs.rc_targets.iter().map(|r| r.target.clone()).collect::<Vec<_>>(),
            "shadowed": inputs.shadowed,
            "settings": entries.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
        });
        return EnvConsolidateOutput {
            text,
            data,
            error: None,
            exit_code: 0,
        };
    }

    let state_dir = configctl_core::state::resolve_state_dir(state_dir_arg);
    let plan_id = configctl_core::state::new_plan_id();
    let plan = configctl_core::plan::build_env_consolidation_plan(
        &loaded,
        &inputs.rc_targets,
        inputs.canonical_current.as_deref(),
        inputs.envd_current.as_ref(),
        inputs.warnings.clone(),
        &plan_id,
        configctl_core::state::now_secs(),
    );
    if let Err(e) = configctl_core::state::save_plan(&state_dir, &plan, &loaded.dir) {
        return consolidate_err(&e, 2);
    }
    let text = super::plan::render_human(&plan);
    EnvConsolidateOutput {
        text,
        data: super::plan::plan_json(&plan),
        error: None,
        exit_code: 0,
    }
}

// ---------------------------------------------------------------------------
// env consolidate --mode move (v1.2 E5 — assisted manual ONLY)
// ---------------------------------------------------------------------------

use configctl_core::envmove;

/// Quote one argv word for POSIX `sh` (single-quote, escaping embedded quotes).
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// `env consolidate --mode move` — assisted manual removal of the now-shadowed
/// original lines. This function never mutates an rc file or the canonical
/// file: `--dry-run` is strictly read-only, and `--emit-patch <file>` writes
/// only the patch file plus one adjacent timestamped backup per touched file.
/// With neither flag it exits 2 with guidance (manual-only by design).
pub fn run_env_consolidate_move(
    profile_arg: Option<&str>,
    home_override: Option<&Path>,
    dry_run: bool,
    emit_patch: Option<&Path>,
) -> EnvConsolidateOutput {
    if !dry_run && emit_patch.is_none() {
        return consolidate_err(
            "env consolidate --mode move is assisted-manual only: nothing was changed. \
             Re-run with --dry-run to preview the tombstone patch, or \
             --emit-patch <file> to write it (with timestamped backups). \
             Apply the patch yourself with `patch -p0 < <file>` from $HOME.",
            2,
        );
    }

    let profile_dir = match super::common::resolve_profile_default(profile_arg) {
        Ok(d) => d,
        Err(e) => return consolidate_err(&e, 2),
    };
    let loaded: LoadedProfile = match profile_load::load_profile_dir(&profile_dir) {
        Ok(l) => l,
        Err(e) => return consolidate_err(&e, 2),
    };

    let home: PathBuf = match home_override {
        Some(h) => h.to_path_buf(),
        None => match dirs::home_dir() {
            Some(h) => h,
            None => return consolidate_err("cannot determine $HOME", 2),
        },
    };

    let entries = configctl_core::plan::canonical_env_entries(&loaded);
    if entries.is_empty() {
        let text = "No [environment] literals in the profile: nothing to move. No changes made.\n"
            .to_string();
        let data = serde_json::json!({
            "mode": "move", "dry_run": dry_run,
            "eligible": [], "ineligible": [],
            "patch_file": null, "backups": [],
            "restore_commands": [], "file_hashes": {}, "warnings": ["no_environment"],
        });
        return EnvConsolidateOutput {
            text,
            data,
            error: None,
            exit_code: 0,
        };
    }

    let assessment = match envmove::assess_move(&home, &entries) {
        Ok(a) => a,
        Err(envmove::MoveError::SecretTrip(name)) => {
            return consolidate_err(
                &format!(
                    "refusing: {name} is secret-like; it must stay a secret reference and can never be consolidated"
                ),
                5,
            );
        }
        Err(envmove::MoveError::Precondition(msg)) => return consolidate_err(&msg, 5),
    };

    let eligible_json: Vec<serde_json::Value> = assessment
        .eligible
        .iter()
        .map(|e| serde_json::json!({"file": e.file, "line": e.line, "name": e.name}))
        .collect();
    let ineligible_json: Vec<serde_json::Value> = assessment
        .ineligible
        .iter()
        .map(|i| {
            serde_json::json!({"file": i.file, "line": i.line, "name": i.name, "reason": i.reason})
        })
        .collect();
    let file_hashes: BTreeMap<String, String> = assessment
        .files
        .iter()
        .filter_map(|f| f.hash.clone().map(|h| (f.file.clone(), h)))
        .collect();

    // ---- human preview (shared by --dry-run and --emit-patch) ----
    let mut text = String::new();
    if emit_patch.is_none() {
        text.push_str("Move preview (dry run) — nothing was written.\n\n");
    } else {
        text.push_str(
            "Move patch emission — rc files and the canonical file are never modified.\n\n",
        );
    }
    for f in &assessment.files {
        match (&f.hash, &f.refused) {
            (_, Some(reason)) => text.push_str(&format!("  {} — {reason}\n", f.file)),
            (Some(hash), None) => {
                text.push_str(&format!(
                    "  {} (sha256 {})\n",
                    f.file,
                    &hash[..16.min(hash.len())]
                ));
                for e in assessment.eligible.iter().filter(|e| e.file == f.file) {
                    text.push_str(&format!(
                        "    line {:<5} {}  tombstone (matches the managed value; include block overrides it)\n",
                        e.line, e.name
                    ));
                }
                for i in assessment.ineligible.iter().filter(|i| i.file == f.file) {
                    if i.line == 0 {
                        continue;
                    }
                    text.push_str(&format!(
                        "    line {:<5} {}  stays: {}\n",
                        i.line, i.name, i.reason
                    ));
                }
            }
            (None, None) => text.push_str(&format!("  {} — unreadable\n", f.file)),
        }
    }
    if assessment.eligible.is_empty() {
        text.push_str("\nNo eligible lines: nothing to tombstone. No changes made.\n");
    } else {
        text.push_str(&format!(
            "\n{} line(s) eligible in {} file(s); {} line(s) stay.\n",
            assessment.eligible.len(),
            assessment
                .files
                .iter()
                .filter(|f| { assessment.eligible.iter().any(|e| e.file == f.file) })
                .count(),
            assessment.ineligible.iter().filter(|i| i.line != 0).count(),
        ));
    }

    // ---- patch emission (only new files written: the patch + backups) ----
    let mut patch_file: Option<String> = None;
    let mut backups: Vec<serde_json::Value> = Vec::new();
    let mut restore_commands: Vec<String> = Vec::new();

    if let Some(patch_path) = emit_patch {
        let now = configctl_core::state::now_secs();
        let patch = envmove::build_patch(&assessment, now);
        // Refuse to overwrite an existing patch unless byte-identical.
        if patch_path.exists() {
            match std::fs::read(patch_path) {
                Ok(cur) if cur == patch.as_bytes() => {
                    text.push_str(&format!(
                        "\nPatch {} already exists with identical content; nothing written.\n",
                        patch_path.display()
                    ));
                }
                _ => {
                    return consolidate_err(
                        &format!(
                            "patch file {} already exists with different content; remove it or choose another path with --emit-patch <file>",
                            patch_path.display()
                        ),
                        5,
                    );
                }
            }
            // Idempotent repeat: report the patch, no backups rewritten.
            let data = serde_json::json!({
                "mode": "move", "dry_run": dry_run,
                "eligible": eligible_json, "ineligible": ineligible_json,
                "patch_file": patch_path.to_string_lossy(),
                "backups": backups, "restore_commands": restore_commands,
                "file_hashes": file_hashes, "warnings": assessment.warnings,
            });
            if dry_run {
                text.push_str("\nNothing was written (dry run also skips patch emission when the patch already exists).\n");
            }
            return EnvConsolidateOutput {
                text,
                data,
                error: None,
                exit_code: 0,
            };
        }

        // Timestamped adjacent backups first (0600, byte-identical, verified).
        let mut touched: Vec<&str> = assessment.eligible.iter().map(|e| e.rel.as_str()).collect();
        touched.sort();
        touched.dedup();
        for rel in touched {
            let abs = home.join(rel);
            let current = match std::fs::read(&abs) {
                Ok(b) => b,
                Err(_) => {
                    return consolidate_err(
                        &format!("{rel} changed since the preview; re-run --dry-run"),
                        5,
                    );
                }
            };
            // TOCTOU narrowing: the bytes backed up must be exactly what the
            // preview assessed; a hand edit in between refuses instead of
            // producing a backup/patch pair that disagrees.
            let assessed = assessment.files.iter().find(|f| f.rel == rel);
            if assessed
                .and_then(|f| f.hash.as_deref())
                .map(|h| configctl_core::hash::file_content_hash(&current) != h)
                .unwrap_or(false)
            {
                return consolidate_err(
                    &format!("{rel} changed since the preview; re-run --dry-run"),
                    5,
                );
            }
            let backup = abs.with_extension(format!(
                "{}configctl-bak-{now}",
                abs.extension()
                    .map(|x| format!("{}.", x.to_string_lossy()))
                    .unwrap_or_default()
            ));
            if backup.exists() {
                match std::fs::read(&backup) {
                    Ok(cur) if cur == current => {}
                    _ => {
                        return consolidate_err(
                            &format!(
                                "backup {} already exists with different content; refusing",
                                backup.display()
                            ),
                            5,
                        );
                    }
                }
            } else {
                if let Err(e) = std::fs::write(&backup, &current) {
                    return consolidate_err(
                        &format!("cannot write backup {}: {e:?}", backup.display()),
                        1,
                    );
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ =
                        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o600));
                }
                // Verify byte-identical.
                match std::fs::read(&backup) {
                    Ok(cur) if cur == current => {}
                    _ => {
                        return consolidate_err(
                            &format!("backup {} failed verification; refusing", backup.display()),
                            1,
                        );
                    }
                }
            }
            let original = format!("~/{rel}");
            restore_commands.push(format!(
                "cp -p {} {}",
                sh_quote(&backup.display().to_string()),
                sh_quote(&abs.display().to_string())
            ));
            backups.push(serde_json::json!({
                "original": original,
                "backup": backup.display().to_string(),
            }));
        }

        if let Some(parent) = patch_path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return consolidate_err(&format!("cannot create patch directory: {e:?}"), 1);
                }
            }
        }
        if let Err(e) = std::fs::write(patch_path, patch.as_bytes()) {
            return consolidate_err(&format!("cannot write patch file: {e:?}"), 1);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(patch_path, std::fs::Permissions::from_mode(0o600));
        }
        patch_file = Some(patch_path.to_string_lossy().into_owned());

        text.push_str(&format!(
            "\nWrote patch {} ({} line(s) in {} file(s)).\n",
            patch_path.display(),
            assessment.eligible.len(),
            backups.len(),
        ));
        if backups.is_empty() {
            text.push_str("No files touched: no backups were needed.\n");
        } else {
            text.push_str("Backups (0600, byte-identical to the pre-patch content):\n");
            for b in &backups {
                text.push_str(&format!(
                    "  {} -> {}\n",
                    b["original"].as_str().unwrap_or("?"),
                    b["backup"].as_str().unwrap_or("?")
                ));
            }
            text.push_str(
                "Restore (rollback cannot restore an out-of-band patch; run these yourself):\n",
            );
            for cmd in &restore_commands {
                text.push_str(&format!("  {cmd}\n"));
            }
        }
        text.push_str(
            "Point-in-time: re-run `configctl env consolidate --mode move --dry-run` before applying; \
             refuse to apply when the file hashes above no longer match. \
             Apply from $HOME with `patch -p0 < <patch file>`.\n",
        );
    } else {
        text.push_str(
            "\nNothing has been changed. To write the patch: \
             `configctl env consolidate --mode move --emit-patch <file> [PROFILE]`.\n",
        );
    }

    let data = serde_json::json!({
        "mode": "move", "dry_run": dry_run,
        "eligible": eligible_json, "ineligible": ineligible_json,
        "patch_file": patch_file,
        "backups": backups, "restore_commands": restore_commands,
        "file_hashes": file_hashes, "warnings": assessment.warnings,
    });
    EnvConsolidateOutput {
        text,
        data,
        error: None,
        exit_code: 0,
    }
}
