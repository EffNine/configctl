//! `configctl apply` — execute exactly the persisted approved plan.
//!
//! Never re-plans. The argument must be a plan ID (never a profile path).

use configctl_core::apply::{ApplyError, ApplyOptions, ApplyReport};
use configctl_core::command::CommandRunner;
use std::path::Path;

/// Result of running the apply command (rendering happens in main).
pub struct ApplyOutput {
    pub report: Option<ApplyReport>,
    pub plan_id: String,
    pub error: Option<ApplyError>,
    pub exit_code: i32,
}

/// True when `arg` looks like a profile path rather than a plan ID (fail
/// closed: refuse to guess).
fn looks_like_profile(arg: &str) -> bool {
    if arg.contains('/') || arg.contains('\\') {
        return true;
    }
    if arg.ends_with(".toml") {
        return true;
    }
    std::path::Path::new(arg).exists() && !arg.contains('-')
}

/// Prompt for approval on a TTY. Returns false on decline, EOF, or non-TTY.
pub fn prompt_approve(plan: &configctl_core::plan::Plan) -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return false;
    }
    let mutating = configctl_core::plan::executable_ops(plan).len();
    eprintln!(
        "Apply {} operation(s) from plan {} (profile {})? [y/N]",
        mutating, plan.plan_id, plan.profile_identity
    );
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(_) => matches!(line.trim().to_lowercase().as_str(), "y" | "yes"),
        Err(_) => false,
    }
}

/// Stable exit code for an apply error (see CLI_SPEC §1.1).
pub fn exit_code_for(e: &ApplyError) -> i32 {
    match e {
        ApplyError::Usage(_) => 2,
        ApplyError::Declined(_) => 4,
        ApplyError::Conflict(_) => 5,
        ApplyError::ProviderUnavailable(_) => 7,
        ApplyError::Privilege(_) => 8,
        ApplyError::OpFailed { .. } => 1,
        ApplyError::CrashSimulated { .. } => 1,
        ApplyError::Internal(_) => 1,
    }
}

/// Resolve `--last`: the most recent persisted plan (any profile).
pub fn resolve_last_plan(state_dir: &Path) -> Result<String, ApplyError> {
    match configctl_core::state::newest_plan_id(state_dir) {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err(ApplyError::Usage(
            "no plans yet; run `configctl plan <profile>` first".into(),
        )),
        Err(e) => Err(ApplyError::Internal(e.to_string())),
    }
}

/// Run apply.
#[allow(clippy::too_many_arguments)]
pub fn run_apply(
    plan_arg: Option<&str>,
    plan_flag: Option<&str>,
    state_dir_override: Option<&str>,
    home_override: Option<&Path>,
    yes: bool,
    dry_run: bool,
    adopt: &[String],
    json: bool,
    runner: &dyn CommandRunner,
) -> ApplyOutput {
    let plan_id: String = match (plan_arg, plan_flag) {
        (Some(a), Some(f)) => {
            if a != f {
                return ApplyOutput {
                    report: None,
                    plan_id: String::new(),
                    error: Some(ApplyError::Usage(
                        "positional plan id and --plan disagree; pass exactly one".into(),
                    )),
                    exit_code: 2,
                };
            }
            a.to_string()
        }
        (Some(a), None) => a.to_string(),
        (None, Some(f)) => f.to_string(),
        (None, None) => {
            return ApplyOutput {
                report: None,
                plan_id: String::new(),
                error: Some(ApplyError::Usage(
                    "apply requires a plan ID (run `configctl plan <profile>` first)".into(),
                )),
                exit_code: 2,
            };
        }
    };
    if looks_like_profile(&plan_id) {
        return ApplyOutput {
            report: None,
            plan_id,
            error: Some(ApplyError::Usage(
                "apply requires a plan ID, not a profile path; run `configctl plan <profile>` first, then `configctl apply <plan-id>`".into(),
            )),
            exit_code: 2,
        };
    }
    if json && !yes && !dry_run {
        return ApplyOutput {
            report: None,
            plan_id,
            error: Some(ApplyError::Usage(
                "--json mode cannot prompt; re-run with --yes".into(),
            )),
            exit_code: 2,
        };
    }
    let home: std::path::PathBuf = match home_override {
        Some(h) => h.to_path_buf(),
        None => match dirs::home_dir() {
            Some(h) => h,
            None => {
                return ApplyOutput {
                    report: None,
                    plan_id,
                    error: Some(ApplyError::Internal("cannot determine $HOME".into())),
                    exit_code: 1,
                };
            }
        },
    };
    let state_dir = configctl_core::state::resolve_state_dir(state_dir_override);
    let opts = ApplyOptions {
        yes,
        dry_run,
        adopt: adopt.to_vec(),
    };
    // Pre-read the plan for the dry-run/no-prompt decline path is handled
    // inside core; here we just forward the prompt callback.
    match configctl_core::apply::apply_plan(
        &state_dir,
        &plan_id,
        &home,
        runner,
        &opts,
        &prompt_approve,
    ) {
        Ok(report) => ApplyOutput {
            report: Some(report),
            plan_id,
            error: None,
            exit_code: 0,
        },
        Err(e) => {
            let code = exit_code_for(&e);
            ApplyOutput {
                report: None,
                plan_id,
                error: Some(e),
                exit_code: code,
            }
        }
    }
}

/// Human-readable error for an apply failure (redaction-safe: messages never
/// contain values by construction).
pub fn error_message(e: &ApplyError) -> String {
    match e {
        ApplyError::Usage(m)
        | ApplyError::Declined(m)
        | ApplyError::Conflict(m)
        | ApplyError::ProviderUnavailable(m)
        | ApplyError::Privilege(m)
        | ApplyError::Internal(m) => m.clone(),
        ApplyError::OpFailed {
            op_id,
            target,
            message,
        } => {
            format!("operation {op_id} ({target}) failed: {message}")
        }
        ApplyError::CrashSimulated { op_id, phase } => {
            format!("simulated crash after {op_id}:{phase}")
        }
    }
}

/// Render a human apply report.
pub fn render_human(report: &ApplyReport) -> String {
    let mut s = String::new();
    if report.dry_run {
        s.push_str(&format!(
            "Dry run — plan {} (no changes made):\n",
            report.plan_id
        ));
    } else {
        s.push_str(&format!("Applied plan {}\n\n", report.plan_id));
    }
    for o in &report.executed {
        let mark = if o.result == "noop" { "[noop]" } else { "[ok]" };
        s.push_str(&format!("  {mark} {} {}\n", o.kind, o.target));
    }
    for n in &report.noop {
        s.push_str(&format!("  [noop] {n}\n"));
    }
    s.push_str(&format!(
        "\n{} operations applied, {} noop. Verify with `configctl verify`.\n",
        report
            .executed
            .iter()
            .filter(|o| o.result != "noop")
            .count(),
        report.noop.len()
            + report
                .executed
                .iter()
                .filter(|o| o.result == "noop")
                .count(),
    ));
    s
}

/// JSON data payload for an apply report.
pub fn report_json(report: &ApplyReport) -> serde_json::Value {
    serde_json::to_value(report).unwrap_or_default()
}
