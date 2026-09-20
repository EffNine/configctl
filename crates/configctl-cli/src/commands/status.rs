//! `configctl status` — one-page summary of state + profile drift (read-only).

use configctl_core::command::CommandRunner;
use configctl_core::state;
use std::collections::BTreeMap;
use std::path::Path;

/// Result of running status.
pub struct StatusOutput {
    pub text: String,
    pub data: serde_json::Value,
    pub error: Option<String>,
    pub exit_code: i32,
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

/// One-page status: state store summary, optionally with profile drift counts.
///
/// Informational: exits 0 even when the profile drifts. A profile that cannot
/// be loaded is a usage error (exit 2).
pub fn run_status(
    profile: Option<&str>,
    state_dir_override: Option<&str>,
    home_override: Option<&Path>,
    runner: &dyn CommandRunner,
) -> StatusOutput {
    let state_dir = state::resolve_state_dir(state_dir_override);
    let now = state::now_secs();

    let mut text = String::from("configctl status\n\n");
    text.push_str(&format!("State          {}\n", state_dir.display()));
    let mut data = serde_json::json!({
        "state_dir": state_dir.display().to_string(),
        "state_initialized": state_dir.is_dir(),
        "plans": [],
        "newest_plan": serde_json::Value::Null,
    });

    if !state_dir.is_dir() {
        text.push_str("               not initialized yet — run `configctl init`\n");
    } else {
        match state::list_plans(&state_dir) {
            Ok(plans) => {
                let mut by_status: BTreeMap<String, usize> = BTreeMap::new();
                for (_, _, status, _) in &plans {
                    *by_status.entry(status.clone()).or_default() += 1;
                }
                let breakdown = by_status
                    .iter()
                    .map(|(k, v)| format!("{v} {k}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                text.push_str(&format!(
                    "Plans          {} total ({breakdown})\n",
                    plans.len()
                ));
                if let Some((id, profile, status, created)) = plans.first() {
                    text.push_str(&format!(
                        "Newest plan    {id} ({profile}, {status}, {})\n",
                        age(now, *created)
                    ));
                    if status == "planned" || status == "approved" {
                        text.push_str("               apply it with `configctl apply --last`\n");
                    }
                    data["newest_plan"] = serde_json::json!({
                        "id": id, "profile": profile, "status": status, "created_at": created,
                    });
                }
                data["plans"] = serde_json::Value::Array(
                    plans
                        .iter()
                        .map(|(id, profile, status, created)| {
                            serde_json::json!({
                                "id": id, "profile": profile,
                                "status": status, "created_at": created,
                            })
                        })
                        .collect(),
                );
            }
            Err(e) => {
                return StatusOutput {
                    text: String::new(),
                    data: serde_json::Value::Null,
                    error: Some(e),
                    exit_code: 1,
                }
            }
        }
    }

    if let Some(p) = profile {
        text.push_str(&format!("\nProfile {p}\n"));
        let out = super::verify::run_verify(p, home_override, false, runner);
        match (out.report, out.error) {
            (Some(rep), _) => {
                let s = &rep.summary;
                text.push_str(&format!("  MATCH        {}\n", s.match_count));
                text.push_str(&format!("  DRIFT        {}\n", s.drift));
                text.push_str(&format!("  MISSING      {}\n", s.missing));
                text.push_str(&format!("  UNMANAGED    {}\n", s.unmanaged));
                text.push_str(&format!("  UNKNOWN      {}\n", s.unknown));
                text.push_str(&format!("  unsupported  {}\n", s.unsupported));
                let needs_work = s.drift + s.missing + s.unmanaged > 0;
                if needs_work {
                    text.push_str(
                        "\n  Next: `configctl plan <profile>` shows how to fix the differences.\n",
                    );
                } else {
                    text.push_str("\n  All managed resources match.\n");
                }
                data["profile"] = serde_json::json!({
                    "name": rep.profile,
                    "profile_hash": rep.profile_hash,
                    "summary": serde_json::to_value(s).unwrap_or_default(),
                });
            }
            (None, Some(e)) => {
                return StatusOutput {
                    text: String::new(),
                    data: serde_json::Value::Null,
                    error: Some(e),
                    exit_code: out.exit_code,
                }
            }
            (None, None) => {
                return StatusOutput {
                    text: String::new(),
                    data: serde_json::Value::Null,
                    error: Some("verify produced no report".into()),
                    exit_code: 1,
                }
            }
        }
    }

    StatusOutput {
        text,
        data,
        error: None,
        exit_code: 0,
    }
}
