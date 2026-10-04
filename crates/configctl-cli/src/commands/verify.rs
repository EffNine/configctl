//! `configctl verify` — read-only drift detection. Never repairs.

use configctl_core::command::CommandRunner;
use configctl_core::observe;
use configctl_core::profile_load::{self, LoadedProfile};
use configctl_core::secrets::{SecretBackend, SecretToolBackend};
use configctl_core::verify::{self, VerifyReport};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Result of running verify.
pub struct VerifyOutput {
    pub report: Option<VerifyReport>,
    pub error: Option<String>,
    /// 0 clean, 3 drift/missing (or strict findings), 2 usage.
    pub exit_code: i32,
}

/// Run verification (read-only; the machine is never modified).
pub fn run_verify(
    profile_arg: &str,
    home_override: Option<&Path>,
    strict: bool,
    runner: &dyn CommandRunner,
) -> VerifyOutput {
    let profile_dir: PathBuf = {
        let p = PathBuf::from(profile_arg);
        if p.exists() {
            p
        } else {
            super::plan::resolve_profile_dir(profile_arg)
        }
    };
    let loaded: LoadedProfile = match profile_load::load_profile_dir(&profile_dir) {
        Ok(l) => l,
        Err(e) => {
            return VerifyOutput {
                report: None,
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
                return VerifyOutput {
                    report: None,
                    error: Some("cannot determine $HOME".into()),
                    exit_code: 2,
                };
            }
        },
    };
    let apt_names = loaded.profile.packages.apt.clone();
    let dnf_names = loaded.profile.packages.dnf.clone();
    let pacman_names = loaded.profile.packages.pacman.clone();
    let file_targets: Vec<String> = loaded
        .profile
        .files
        .iter()
        .map(|f| f.target.clone())
        .collect();
    let git_wanted = loaded.profile.git.is_some();
    let services: Vec<String> = loaded
        .profile
        .services
        .iter()
        .map(|s| s.name.clone())
        .collect();
    let mut secret_refs: BTreeSet<String> = BTreeSet::new();
    let mut env_names: Vec<String> = Vec::new();
    if let Some(env) = &loaded.profile.environment {
        for (k, v) in env {
            match v {
                configctl_core::profile::EnvLiteral::Value(_) => env_names.push(k.clone()),
                configctl_core::profile::EnvLiteral::Secret { secret, .. } => {
                    secret_refs.insert(secret.clone());
                }
            }
        }
    }
    if let Some(m) = &loaded.manifest {
        for s in &m.secrets {
            secret_refs.insert(s.secret_ref.clone());
        }
    }
    env_names.sort();
    env_names.dedup();
    let secret_refs: Vec<String> = secret_refs.into_iter().collect();
    let backend = SecretToolBackend { runner };
    let observed = observe::observe(
        runner,
        &home,
        &apt_names,
        &dnf_names,
        &pacman_names,
        &file_targets,
        git_wanted,
        &services,
        &secret_refs,
        &|r| backend.exists(r),
        &env_names,
    );
    let report = verify::verify(&loaded, &observed);
    let exit_code = match verify::outcome(&report, strict) {
        verify::VerifyOutcome::Clean => 0,
        verify::VerifyOutcome::Drift | verify::VerifyOutcome::StrictFindings => 3,
    };
    VerifyOutput {
        report: Some(report),
        error: None,
        exit_code,
    }
}

/// Render human output.
pub fn render_human(report: &VerifyReport) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "Environment Verification — {}\n\n",
        report.profile
    ));
    // Per-category counts.
    let mut cats: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    for r in &report.results {
        let e = cats.entry(r.resource.as_str()).or_insert((0, 0));
        e.1 += 1;
        if r.status == verify::CheckStatus::Match {
            e.0 += 1;
        }
    }
    for (cat, (ok, total)) in &cats {
        let verdict = if ok == total { "PASS" } else { "FAIL" };
        s.push_str(&format!("{cat:12} {ok}/{total}    {verdict}\n"));
    }
    let problems: Vec<&verify::CheckResult> = report
        .results
        .iter()
        .filter(|r| r.status != verify::CheckStatus::Match)
        .collect();
    if !problems.is_empty() {
        s.push_str("\nFindings:\n");
        for r in problems {
            s.push_str(&format!(
                "  {:?} {} {} — {}\n",
                r.status, r.resource, r.target, r.detail
            ));
        }
    } else {
        s.push_str("\nAll resources match.\n");
    }
    s
}
