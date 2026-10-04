//! `configctl doctor` — diagnostics only. Always exit 0 unless the state
//! directory itself is unusable. Surfaces interrupted applies with per-op
//! recovery classification so recovery stays explicit.

use configctl_core::command::{CommandRequest, CommandRunner};

/// One interrupted plan for the report.
#[derive(Debug, Clone)]
pub struct InterruptedPlan {
    pub plan_id: String,
    pub profile: String,
    pub status: String,
    pub ops: Vec<configctl_core::rollback::OpRecovery>,
}

pub struct DoctorOutput {
    pub os: String,
    pub arch: String,
    pub distro: String,
    pub package_manager: String,
    pub systemd_user: String,
    pub secret_backend: String,
    pub state_dir: String,
    pub state_ok: bool,
    pub plans: usize,
    pub interrupted: Vec<InterruptedPlan>,
    pub error: Option<String>,
}

fn probe(runner: &dyn CommandRunner, program: &str, args: &[&str]) -> bool {
    let req = CommandRequest::new(program, args.iter().copied()).output_cap(8 * 1024);
    matches!(runner.run(&req), Ok(o) if o.status == Some(0))
}

/// Run diagnostics (read-only; never mutates).
pub fn run_doctor(state_dir_override: Option<&str>, runner: &dyn CommandRunner) -> DoctorOutput {
    let state_dir = configctl_core::state::resolve_state_dir(state_dir_override);
    let distro = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                l.trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"')
                    .to_string()
            })
        })
        .unwrap_or_else(|| "Linux".into());
    let package_manager = if probe(runner, "dpkg-query", &["--version"]) {
        "apt (dpkg-query available)".into()
    } else if probe(runner, "dnf", &["--version"]) {
        "dnf (dnf available)".into()
    } else if probe(runner, "pacman", &["--version"]) {
        "pacman (pacman available)".into()
    } else {
        "unavailable".into()
    };
    let systemd_user = if probe(runner, "systemctl", &["--user", "list-units"]) {
        "available".into()
    } else {
        "unavailable".into()
    };
    let secret_backend = if std::env::var_os("CONFIGCTL_SECRET_TEST_DIR").is_some() {
        "test backend (CONFIGCTL_SECRET_TEST_DIR)".into()
    } else if probe(runner, "secret-tool", &["--version"]) {
        "Secret Service (secret-tool)".into()
    } else {
        "unavailable (install libsecret / secret-tool)".into()
    };
    let (state_ok, plans, interrupted, error) = match configctl_core::state::list_plans(&state_dir)
    {
        Err(e) => (false, 0, Vec::new(), Some(e)),
        Ok(list) => {
            let mut interrupted = Vec::new();
            for (id, profile, status, _) in &list {
                if status == "applying" || status == "partial" {
                    let ops =
                        configctl_core::rollback::classify_plan(&state_dir, id).unwrap_or_default();
                    interrupted.push(InterruptedPlan {
                        plan_id: id.clone(),
                        profile: profile.clone(),
                        status: status.clone(),
                        ops,
                    });
                }
            }
            (true, list.len(), interrupted, None)
        }
    };
    DoctorOutput {
        os: "linux".into(),
        arch: std::env::consts::ARCH.into(),
        distro,
        package_manager,
        systemd_user,
        secret_backend,
        state_dir: state_dir.to_string_lossy().into_owned(),
        state_ok,
        plans,
        interrupted,
        error,
    }
}

/// Render human output.
pub fn render_human(out: &DoctorOutput) -> String {
    let mut s = String::new();
    s.push_str(&format!("Platform              {} {}\n", out.os, out.arch));
    s.push_str(&format!("Distribution          {}\n", out.distro));
    s.push_str(&format!("Package manager       {}\n", out.package_manager));
    s.push_str(&format!("Systemd user          {}\n", out.systemd_user));
    s.push_str(&format!("Secret backend        {}\n", out.secret_backend));
    s.push_str(&format!(
        "State                 {} ({})\n",
        if out.state_ok { "OK" } else { "UNUSABLE" },
        out.state_dir
    ));
    s.push_str(&format!("Plans                 {}\n", out.plans));
    if out.interrupted.is_empty() {
        s.push_str("Interrupted apply     none\n");
    } else {
        s.push_str("Interrupted apply:\n");
        for p in &out.interrupted {
            s.push_str(&format!(
                "  plan {} ({}, {})\n",
                p.plan_id, p.profile, p.status
            ));
            for op in &p.ops {
                let class = match op.class {
                    configctl_core::rollback::RecoveryClass::SafeToResume => "safe to resume",
                    configctl_core::rollback::RecoveryClass::RequiresRollback => {
                        "requires rollback"
                    }
                    configctl_core::rollback::RecoveryClass::RequiresManual => {
                        "requires manual intervention"
                    }
                    configctl_core::rollback::RecoveryClass::Unknown => "unknown",
                };
                s.push_str(&format!(
                    "    {} {} [{} after {}] — {}\n",
                    op.op_id,
                    op.target,
                    class,
                    op.last_phase.as_deref().unwrap_or("never started"),
                    op.reason
                ));
            }
            s.push_str(&format!(
                "  Recover with: configctl rollback --plan {}\n",
                p.plan_id
            ));
        }
    }
    s
}
