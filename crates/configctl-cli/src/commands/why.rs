//! `configctl why <target>` — ownership and history for one resource
//! (read-only).
//!
//! Answers the beginner question "where did this file come from and who
//! owns it?": state-store ownership, on-disk facts, and the most recent plan
//! operation that touched the target, with its journal outcome and backup.

use configctl_core::state;
use std::path::{Path, PathBuf};

/// Result of running why.
pub struct WhyOutput {
    pub text: String,
    pub data: serde_json::Value,
    pub error: Option<String>,
    pub exit_code: i32,
}

fn internal(msg: impl Into<String>) -> WhyOutput {
    WhyOutput {
        text: String::new(),
        data: serde_json::Value::Null,
        error: Some(msg.into()),
        exit_code: 1,
    }
}

/// Normalize a user-supplied target to the portable locator used by the
/// store: `~/.gitconfig` or `/home/u/.gitconfig` -> `~/.gitconfig`.
/// Anything outside `$HOME` is not a manageable file target.
fn to_locator(target: &str, home: &Path) -> Option<String> {
    if target == "~" {
        return None;
    }
    if let Some(rest) = target.strip_prefix("~/") {
        return Some(format!("~/{rest}"));
    }
    let p = PathBuf::from(target);
    if p.is_absolute() {
        if let Ok(rel) = p.strip_prefix(home) {
            return Some(format!("~/{}", rel.display()));
        }
    }
    None
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

fn age(now: i64, then: i64) -> String {
    let d = now.saturating_sub(then);
    if d < 60 {
        "just now".into()
    } else if d < 3_600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3_600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}

/// Explain one file target: ownership, disk facts, last operation.
pub fn run_why(
    target: &str,
    state_dir_override: Option<&str>,
    home_override: Option<&Path>,
) -> WhyOutput {
    let home = match home_override
        .map(|h| h.to_path_buf())
        .or_else(dirs::home_dir)
    {
        Some(h) => h,
        None => return internal("cannot determine $HOME"),
    };
    let state_dir = state::resolve_state_dir(state_dir_override);
    let Some(locator) = to_locator(target, &home) else {
        return WhyOutput {
            text: String::new(),
            data: serde_json::Value::Null,
            error: Some(format!(
                "why expects a file target under $HOME, e.g. `~/.gitconfig` (got {target:?})"
            )),
            exit_code: 2,
        };
    };
    let abs = home.join(locator.trim_start_matches("~/"));
    let now = state::now_secs();

    let meta = std::fs::symlink_metadata(&abs).ok();
    let exists = meta.is_some();
    let size = meta.as_ref().map(|m| m.len());
    let is_symlink = meta.as_ref().map(|m| m.file_type().is_symlink());

    let resource = match state::find_resource(&state_dir, "file", &locator) {
        Ok(r) => r,
        Err(e) => return internal(e),
    };

    // Most recent plan touching this target (bounded scan, newest first).
    let mut last_op: Option<serde_json::Value> = None;
    if state_dir.is_dir() {
        if let Ok(plans) = state::list_plans(&state_dir) {
            for (id, profile, status, created) in plans.iter().take(20) {
                let Ok((plan, _, _)) = state::load_plan(&state_dir, id) else {
                    continue;
                };
                let Some(op) = plan.operations.iter().find(|o| o.target == locator) else {
                    continue;
                };
                let last_journal = state::journal_for_plan(&state_dir, id)
                    .ok()
                    .and_then(|entries| entries.into_iter().rfind(|e| e.op_id == op.id));
                let (phase, backup) = match &last_journal {
                    Some(e) => (Some(e.phase.clone()), e.backup_sha.clone()),
                    None => (None, None),
                };
                last_op = Some(serde_json::json!({
                    "plan_id": id,
                    "plan_profile": profile,
                    "plan_status": status,
                    "plan_created_at": created,
                    "op_id": op.id,
                    "kind": format!("{:?}", op.kind),
                    "action_class": op.action_class.as_str(),
                    "journal_phase": phase,
                    "backup_sha": backup,
                }));
                break;
            }
        }
    }

    let mut text = format!("{locator}\n\n");
    match (&meta, is_symlink) {
        (Some(_), Some(true)) => {
            text.push_str("  file         symlink (configctl refuses symlink targets)\n")
        }
        (Some(m), _) => text.push_str(&format!("  file         exists ({} bytes)\n", m.len())),
        (None, _) => text.push_str("  file         not present on disk\n"),
    }
    match &resource {
        Some(r) if r.owner_profile.is_some() => {
            text.push_str(&format!(
                "  managed by   profile {:?}\n",
                r.owner_profile.as_deref().unwrap_or("-")
            ));
            if let Some(fp) = &r.fingerprint {
                text.push_str(&format!("  fingerprint  {} (sha256)\n", short(fp)));
            }
            text.push_str(&format!(
                "  updated      {} ({})\n",
                r.updated_at,
                age(now, r.updated_at)
            ));
        }
        _ => {
            text.push_str("  managed by   nothing — no profile owns this file\n");
            text.push_str(
                "               a plan that targets it reports a conflict; adopt deliberately\n",
            );
        }
    }
    if let Some(op) = &last_op {
        text.push_str("\n  last operation\n");
        let plan_age = op["plan_created_at"]
            .as_i64()
            .map(|t| age(now, t))
            .unwrap_or_else(|| "-".to_string());
        text.push_str(&format!(
            "    plan       {} ({}, {}, {})\n",
            op["plan_id"].as_str().unwrap_or("-"),
            op["plan_profile"].as_str().unwrap_or("-"),
            op["plan_status"].as_str().unwrap_or("-"),
            plan_age,
        ));
        text.push_str(&format!(
            "    op         {} {}\n",
            op["op_id"].as_str().unwrap_or("-"),
            op["kind"].as_str().unwrap_or("-")
        ));
        match op["journal_phase"].as_str() {
            Some(phase) => {
                let backup = op["backup_sha"].as_str().map(short).unwrap_or("none");
                text.push_str(&format!("    journal    {phase} (backup {backup})\n"));
            }
            None => text.push_str("    journal    (no journal entries)\n"),
        }
        if op["plan_status"].as_str() == Some("applied")
            || op["plan_status"].as_str() == Some("partial")
        {
            text.push_str(&format!(
                "    rollback   configctl rollback --plan {}\n",
                op["plan_id"].as_str().unwrap_or("-")
            ));
        }
    }

    WhyOutput {
        text,
        data: serde_json::json!({
            "target": locator,
            "exists": exists,
            "size_bytes": size,
            "is_symlink": is_symlink,
            "managed_by": resource.as_ref().and_then(|r| r.owner_profile.clone()),
            "fingerprint": resource.as_ref().and_then(|r| r.fingerprint.clone()),
            "updated_at": resource.as_ref().map(|r| r.updated_at),
            "last_operation": last_op,
        }),
        error: None,
        exit_code: 0,
    }
}
