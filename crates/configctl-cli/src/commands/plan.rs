//! `configctl plan` — deterministic, non-mutating diff.
//!
//! Pipeline: `PROFILE + OBSERVED → NORMALIZE → DIFF → PLAN → PERSIST → HASH`.
//! Never mutates the machine: the only write is the persisted plan document
//! inside the state directory.

use configctl_core::command::CommandRunner;
use configctl_core::observe::{self, ObservedState};
use configctl_core::plan::{self, Plan};
use configctl_core::profile_load::{self, LoadedProfile};
use configctl_core::secrets::{SecretBackend, SecretToolBackend};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Result of running the plan command.
pub struct PlanOutput {
    pub plan: Option<Plan>,
    pub profile_dir: Option<PathBuf>,
    pub out_path: Option<PathBuf>,
    pub error: Option<PlanError>,
}

/// Usage/validation failure (exit 2) vs conflict signal.
#[derive(Debug, Clone)]
pub struct PlanError {
    pub message: String,
    pub hint: String,
}

/// Resolve a profile argument (path or name) to a bundle directory.
pub fn resolve_profile_dir(arg: &str) -> PathBuf {
    let p = PathBuf::from(arg);
    if p.exists() {
        return p;
    }
    // Name lookup under XDG config.
    let base = config_profiles_dir().join(arg);
    if base.exists() {
        return base;
    }
    p
}

fn config_profiles_dir() -> PathBuf {
    if let Some(cfg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(cfg).join("configctl/profiles")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config/configctl/profiles")
    } else {
        PathBuf::from("profiles")
    }
}

/// Collect declared secret refs + literal env names from a loaded profile.
fn secret_refs_and_env(loaded: &LoadedProfile) -> (Vec<String>, Vec<String>) {
    let mut refs: BTreeSet<String> = BTreeSet::new();
    let mut env_names: Vec<String> = Vec::new();
    if let Some(env) = &loaded.profile.environment {
        for (k, v) in env {
            match v {
                configctl_core::profile::EnvLiteral::Value(_) => env_names.push(k.clone()),
                configctl_core::profile::EnvLiteral::Secret { secret, .. } => {
                    refs.insert(secret.clone());
                }
            }
        }
    }
    if let Some(m) = &loaded.manifest {
        for s in &m.secrets {
            refs.insert(s.secret_ref.clone());
        }
    }
    env_names.sort();
    env_names.dedup();
    (refs.into_iter().collect(), env_names)
}

/// Run plan: load profile → observe → diff → persist. Read-only w.r.t. the
/// machine (state dir is the only write).
#[allow(clippy::too_many_arguments)]
pub fn run_plan(
    profile_arg: &str,
    state_dir_override: Option<&str>,
    home_override: Option<&Path>,
    runner: &dyn CommandRunner,
    plan_id_override: Option<&str>,
    created_at_override: Option<i64>,
) -> PlanOutput {
    let profile_dir = resolve_profile_dir(profile_arg);
    let loaded: LoadedProfile = match profile_load::load_profile_dir(&profile_dir) {
        Ok(l) => l,
        Err(e) => {
            return PlanOutput {
                plan: None,
                profile_dir: Some(profile_dir),
                out_path: None,
                error: Some(PlanError {
                    message: e,
                    hint: "fix the profile and re-run plan".into(),
                }),
            };
        }
    };
    let home: PathBuf = match home_override {
        Some(h) => h.to_path_buf(),
        None => match dirs::home_dir() {
            Some(h) => h,
            None => {
                return PlanOutput {
                    plan: None,
                    profile_dir: Some(profile_dir),
                    out_path: None,
                    error: Some(PlanError {
                        message: "cannot determine $HOME".into(),
                        hint: "set $HOME and retry".into(),
                    }),
                };
            }
        },
    };
    let state_dir = configctl_core::state::resolve_state_dir(state_dir_override);

    // Ownership snapshot (missing state dir ⇒ empty ownership).
    let owned: BTreeSet<(String, String)> =
        configctl_core::state::ownership_for_profile(&state_dir, &loaded.identity)
            .unwrap_or_default();

    // Observe.
    let apt_names = loaded.profile.packages.apt.clone();
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
    let (secret_refs, env_names) = secret_refs_and_env(&loaded);
    let backend = SecretToolBackend { runner };
    let observed: ObservedState = observe::observe(
        runner,
        &home,
        &apt_names,
        &file_targets,
        git_wanted,
        &services,
        &secret_refs,
        &|r| backend.exists(r),
        &env_names,
    );

    let plan_id = plan_id_override
        .map(|s| s.to_string())
        .unwrap_or_else(configctl_core::state::new_plan_id);
    let created_at = created_at_override.unwrap_or_else(configctl_core::state::now_secs);
    let plan = plan::build_plan(&loaded, &observed, &owned, &plan_id, created_at);

    // Persist (immutable; refuses conflicting overwrite).
    match configctl_core::state::save_plan(&state_dir, &plan, &loaded.dir) {
        Ok(doc_path) => PlanOutput {
            plan: Some(plan),
            profile_dir: Some(profile_dir),
            out_path: Some(doc_path),
            error: None,
        },
        Err(e) => PlanOutput {
            plan: Some(plan),
            profile_dir: Some(profile_dir),
            out_path: None,
            error: Some(PlanError {
                message: e,
                hint: "inspect the state directory and retry".into(),
            }),
        },
    }
}

/// Render human output for a plan.
pub fn render_human(plan: &Plan) -> String {
    let mut s = String::new();
    s.push_str(&format!("PLAN {}\n\n", plan.profile_identity));
    // Group by provider.
    let groups = [
        ("apt", "Packages:"),
        ("files", "Files:"),
        ("env", "Environment:"),
        ("systemd", "Services:"),
        ("git", "Git:"),
        ("core", "Other:"),
    ];
    for (prov, title) in groups {
        let ops: Vec<&configctl_core::plan::Operation> = plan
            .operations
            .iter()
            .filter(|o| o.provider == prov)
            .collect();
        if ops.is_empty() {
            continue;
        }
        s.push_str(title);
        s.push('\n');
        for o in ops {
            s.push_str(&format!("  {} {}\n", kind_glyph(&o.kind), o.summary));
        }
        s.push('\n');
    }
    if !plan.conflicts.is_empty() {
        s.push_str(&format!("{} conflict(s):\n", plan.conflicts.len()));
        for c in &plan.conflicts {
            s.push_str(&format!("  ! {}: {}\n", c.target, c.message));
        }
        s.push('\n');
    }
    if !plan.warnings.is_empty() {
        s.push_str("warnings:\n");
        for w in &plan.warnings {
            s.push_str(&format!("  ! [{}] {}\n", w.code, w.message));
        }
        s.push('\n');
    }
    s.push_str(&format!(
        "plan id: {}\nplan hash: {}\nNo changes made. Run `configctl apply {}` to execute this plan.\n",
        plan.plan_id, plan.plan_hash, plan.plan_id
    ));
    s
}

fn kind_glyph(k: &configctl_core::plan::OperationKind) -> &'static str {
    use configctl_core::plan::OperationKind as K;
    match k {
        K::PackageInstall => "+",
        K::PackageVersionMismatch => "~",
        K::FileCreate => "+",
        K::FileUpdate => "~",
        K::FileConflict => "!",
        K::EnvironmentSchemaChange => "+",
        K::ServiceEnable => "+",
        K::ServiceDisable => "-",
        K::GitConfigChange => "~",
        K::NoOp => "=",
        K::Unsupported => "?",
    }
}

/// JSON data payload for the plan envelope.
pub fn plan_json(plan: &Plan) -> serde_json::Value {
    serde_json::to_value(plan).unwrap_or_default()
}
