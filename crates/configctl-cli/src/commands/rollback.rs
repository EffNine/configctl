//! `configctl rollback` — explicit recovery from applied/partial plans.
//!
//! Restores file/env content from content-addressed backups (reverse order).
//! Packages are never auto-removed; services/git without snapshots are
//! reported for manual handling. Requires the mutation lock.

use configctl_core::command::CommandRunner;
use configctl_core::rollback::{RollbackError, RollbackOptions, RollbackReport};
use std::path::Path;

/// Result of the rollback command.
pub struct RollbackOutput {
    pub report: Option<RollbackReport>,
    pub plans: Option<Vec<(String, String, String, i64)>>,
    pub error: Option<RollbackError>,
    pub exit_code: i32,
}

pub fn error_message(e: &RollbackError) -> String {
    match e {
        RollbackError::Usage(m)
        | RollbackError::Declined(m)
        | RollbackError::Conflict(m)
        | RollbackError::Internal(m) => m.clone(),
    }
}

fn exit_code(e: &RollbackError) -> i32 {
    match e {
        RollbackError::Usage(_) => 2,
        RollbackError::Declined(_) => 4,
        RollbackError::Conflict(_) => 5,
        RollbackError::Internal(_) => 1,
    }
}

/// Prompt for rollback approval on a TTY.
fn prompt_approve(report: &RollbackReport) -> bool {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprintln!(
        "Roll back plan {} (restore {}, remove {}, {} manual)? [y/N]",
        report.plan_id,
        report.restored.len(),
        report.removed.len(),
        report.manual.len()
    );
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(_) => matches!(line.trim().to_lowercase().as_str(), "y" | "yes"),
        Err(_) => false,
    }
}

/// Run rollback.
///
/// - `--list`: show rollback candidates (no mutation).
/// - positional `TARGET`: a plan id, profile name (latest plan), or `~/...`
///   file target (targeted single-file restore).
/// - `--plan <ID>`: explicit plan id.
#[allow(clippy::too_many_arguments)]
pub fn run_rollback(
    target: Option<&str>,
    plan_flag: Option<&str>,
    list: bool,
    state_dir_override: Option<&str>,
    home_override: Option<&Path>,
    yes: bool,
    dry_run: bool,
    json: bool,
    _runner: &dyn CommandRunner,
) -> RollbackOutput {
    let state_dir = configctl_core::state::resolve_state_dir(state_dir_override);
    if list {
        return match configctl_core::state::list_plans(&state_dir) {
            Ok(plans) => RollbackOutput {
                report: None,
                plans: Some(plans),
                error: None,
                exit_code: 0,
            },
            Err(e) => RollbackOutput {
                report: None,
                plans: None,
                error: Some(RollbackError::Internal(e)),
                exit_code: 1,
            },
        };
    }
    if json && !yes && !dry_run {
        return RollbackOutput {
            report: None,
            plans: None,
            error: Some(RollbackError::Usage(
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
                return RollbackOutput {
                    report: None,
                    plans: None,
                    error: Some(RollbackError::Internal("cannot determine $HOME".into())),
                    exit_code: 1,
                };
            }
        },
    };
    let opts = RollbackOptions { yes, dry_run };
    // Resolve what to roll back.
    let (explicit_plan, file_target): (Option<String>, Option<String>) = match (target, plan_flag) {
        (Some(t), Some(f)) => {
            if t == f {
                (Some(t.to_string()), None)
            } else {
                return RollbackOutput {
                    report: None,
                    plans: None,
                    error: Some(RollbackError::Usage(
                        "positional target and --plan disagree; pass exactly one".into(),
                    )),
                    exit_code: 2,
                };
            }
        }
        (Some(t), None) => {
            if t.starts_with("~/") || t == "~" {
                (None, Some(t.to_string()))
            } else {
                (Some(t.to_string()), None)
            }
        }
        (None, Some(f)) => (Some(f.to_string()), None),
        (None, None) => {
            return RollbackOutput {
                report: None,
                plans: None,
                error: Some(RollbackError::Usage(
                    "rollback requires a plan ID, profile name, or file target (or --list)".into(),
                )),
                exit_code: 2,
            };
        }
    };
    if let Some(file) = file_target {
        return match configctl_core::rollback::rollback_target(&state_dir, &file, &home, dry_run) {
            Ok(mut rep) => {
                rep.dry_run = dry_run;
                RollbackOutput {
                    report: Some(rep),
                    plans: None,
                    error: None,
                    exit_code: 0,
                }
            }
            Err(e) => {
                let c = exit_code(&e);
                RollbackOutput {
                    report: None,
                    plans: None,
                    error: Some(e),
                    exit_code: c,
                }
            }
        };
    }
    let mut plan_id = explicit_plan.unwrap();
    // Profile name → latest plan for that profile.
    if !plan_id.contains('-') {
        match latest_for_profile(&state_dir, &plan_id) {
            Some(id) => plan_id = id,
            None => {
                return RollbackOutput {
                    report: None,
                    plans: None,
                    error: Some(RollbackError::Usage(format!(
                        "no plans found for profile {plan_id:?}"
                    ))),
                    exit_code: 2,
                };
            }
        }
    }
    match configctl_core::rollback::rollback_plan(
        &state_dir,
        &plan_id,
        &home,
        &opts,
        &prompt_approve,
    ) {
        Ok(rep) => RollbackOutput {
            report: Some(rep),
            plans: None,
            error: None,
            exit_code: 0,
        },
        Err(e) => {
            let c = exit_code(&e);
            RollbackOutput {
                report: None,
                plans: None,
                error: Some(e),
                exit_code: c,
            }
        }
    }
}

fn latest_for_profile(state_dir: &Path, profile: &str) -> Option<String> {
    let plans = configctl_core::state::list_plans(state_dir).ok()?;
    plans
        .into_iter()
        .find(|(_, p, _, _)| p == profile)
        .map(|(id, _, _, _)| id)
}

/// Render human output.
pub fn render_human_list(plans: &[(String, String, String, i64)]) -> String {
    if plans.is_empty() {
        return "No plans recorded.\n".into();
    }
    let mut s = String::from("Rollback candidates (newest first):\n\n");
    for (id, profile, status, created) in plans {
        s.push_str(&format!("  {id}  {profile}  {status}  ({created})\n"));
    }
    s
}

/// Render a rollback report.
pub fn render_human(rep: &RollbackReport) -> String {
    let mut s = String::new();
    if rep.dry_run {
        s.push_str(&format!(
            "Dry run — rollback plan {} (no changes made):\n",
            rep.plan_id
        ));
    } else {
        s.push_str(&format!("Rolled back plan {}\n\n", rep.plan_id));
    }
    for t in &rep.restored {
        s.push_str(&format!("  [restored] {t}\n"));
    }
    for t in &rep.removed {
        s.push_str(&format!("  [removed] {t}\n"));
    }
    for m in &rep.manual {
        s.push_str(&format!("  [manual] {m}\n"));
    }
    if rep.restored.is_empty() && rep.removed.is_empty() && rep.manual.is_empty() {
        s.push_str("  (nothing to restore)\n");
    }
    s
}
