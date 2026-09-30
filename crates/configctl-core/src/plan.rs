//! Deterministic plan/diff engine (P3).
//!
//! Pipeline: `PROFILE + OBSERVED → NORMALIZE → DIFF → PLAN → PERSIST → HASH`.
//! Pure and non-mutating: planning only reads the profile bundle, the observed
//! snapshot, and ownership records. It never writes to the machine.
//!
//! Determinism: operations are sorted by `(provider_rank, target)`; the plan
//! hash covers only semantic content (never `created_at`/`plan_id`).

use crate::classify::PlanActionClass;
use crate::observe::ObservedState;
use crate::profile::EnvLiteral;
use crate::profile_load::LoadedProfile;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Plan schema version.
pub const PLAN_SCHEMA_VERSION: u32 = 1;

/// Resource classification (P3 diff rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiffStatus {
    Match,
    Create,
    Update,
    Missing,
    Conflict,
    Unmanaged,
    Unsupported,
    Unknown,
}

/// Operation kinds (superset of executable actions; unsupported providers are
/// represented honestly as `Unsupported`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationKind {
    PackageInstall,
    PackageVersionMismatch,
    FileCreate,
    FileUpdate,
    FileConflict,
    EnvironmentSchemaChange,
    /// v1.2: write the canonical managed shell env file
    /// (`~/.config/configctl/env.sh`), composed from the profile's
    /// `[environment]` literals.
    EnvFileWrite,
    /// v1.2: append the marker-delimited include block to a shell startup
    /// file so it reads the canonical managed env file.
    IncludeLineAdd,
    ServiceEnable,
    ServiceDisable,
    GitConfigChange,
    NoOp,
    Unsupported,
}

/// One planned operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    /// Stable id within the plan (`op-0001`, ... in sorted order).
    pub id: String,
    /// Provider that would execute it (`apt`, `files`, `env`, `systemd`, `git`, `core`).
    pub provider: String,
    pub kind: OperationKind,
    /// Canonical target (package name, `~/...` path, unit, `VAR`, ...).
    pub target: String,
    /// Human summary (redaction-safe: never values, only names/refs).
    pub summary: String,
    /// `low` | `medium` | `high`.
    pub risk: String,
    /// Content hash the operation expects before execution (when known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_before: Option<String>,
    /// Content hash desired after execution (when known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_after: Option<String>,
    /// Whether rollback is supported for this op.
    pub rollback: RollbackSupport,
    /// v1.1 execution policy class (see [`PlanActionClass`]).
    ///
    /// Old plans without this field deserialize as `SAFE_REPRODUCE`,
    /// preserving v1 execution semantics exactly.
    #[serde(default = "default_action_class")]
    pub action_class: PlanActionClass,
    /// Redaction-safe details.
    #[serde(default)]
    pub details: BTreeMap<String, String>,
}

/// Default class for plans persisted before v1.1 (v1 semantics: every
/// executable op was deemed safe).
fn default_action_class() -> PlanActionClass {
    PlanActionClass::SafeReproduce
}

/// Execution class for a freshly built operation kind.
fn class_for_kind(kind: &OperationKind) -> PlanActionClass {
    match kind {
        OperationKind::PackageInstall
        | OperationKind::FileCreate
        | OperationKind::FileUpdate
        | OperationKind::EnvironmentSchemaChange
        | OperationKind::EnvFileWrite
        | OperationKind::IncludeLineAdd
        | OperationKind::ServiceEnable
        | OperationKind::ServiceDisable
        | OperationKind::GitConfigChange => PlanActionClass::SafeReproduce,
        OperationKind::FileConflict
        | OperationKind::NoOp
        | OperationKind::PackageVersionMismatch => PlanActionClass::Manual,
        OperationKind::Unsupported => PlanActionClass::Unsupported,
    }
}

/// Rollback honesty per operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RollbackSupport {
    Supported,
    Partial,
    Unsupported,
}

/// A blocking conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    pub target: String,
    pub code: String,
    pub message: String,
}

/// A non-blocking warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanWarning {
    pub code: String,
    pub message: String,
}

/// The persisted plan document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub schema_version: u32,
    pub plan_id: String,
    pub profile_identity: String,
    pub profile_hash: String,
    pub observed_state_fingerprint: String,
    /// Unix seconds (informational; excluded from the plan hash).
    pub created_at: i64,
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub warnings: Vec<PlanWarning>,
    #[serde(default)]
    pub conflicts: Vec<Conflict>,
    pub plan_hash: String,
}

/// Ownership snapshot: set of `(kind, locator)` managed by this profile.
/// `kind` is `file` for file targets; locator is the declared `~/...` target.
pub type Ownership = BTreeSet<(String, String)>;

/// Build a deterministic plan from a loaded profile + observed state.
///
/// `owned` lists resources the state store already attributes to this profile.
/// `managed_env_target` is the env file configctl owns
/// (`~/.config/environment.d/90-configctl.conf`).
pub fn build_plan(
    loaded: &LoadedProfile,
    observed: &ObservedState,
    owned: &Ownership,
    plan_id: &str,
    created_at: i64,
) -> Plan {
    let mut operations: Vec<Operation> = Vec::new();
    let mut warnings: Vec<PlanWarning> = Vec::new();
    let mut conflicts: Vec<Conflict> = Vec::new();
    let profile = &loaded.profile;

    // ---- Packages (rank 1) ----
    let mut apt = profile.packages.apt.clone();
    apt.sort();
    apt.dedup();
    for name in &apt {
        if observed.packages_unavailable {
            operations.push(mk_op(
                "apt",
                OperationKind::Unsupported,
                name,
                format!("package {name}: package manager unavailable"),
                "low",
                None,
                None,
                RollbackSupport::Unsupported,
            ));
            warnings.push(PlanWarning {
                code: "packages_unavailable".into(),
                message: format!("package {name}: manager unavailable; marked unsupported"),
            });
            continue;
        }
        match observed.packages.get(name) {
            None => operations.push(mk_op(
                "apt",
                OperationKind::PackageInstall,
                name,
                format!("package {name}: install via apt"),
                "medium",
                None,
                None,
                RollbackSupport::Unsupported,
            )),
            Some(installed) => {
                if let Some(lock) = loaded.lock.as_ref().and_then(|l| l.apt.get(name)) {
                    if lock != installed {
                        operations.push(mk_op(
                            "apt",
                            OperationKind::PackageVersionMismatch,
                            name,
                            format!("package {name}: installed {installed} differs from lock {lock} (report-only)"),
                            "low",
                            None,
                            None,
                            RollbackSupport::Unsupported,
                        ));
                        warnings.push(PlanWarning {
                            code: "package_version_drift".into(),
                            message: format!("package {name}: installed version differs from lock; v1 never downgrades"),
                        });
                    }
                }
            }
        }
    }

    // ---- Files (rank 2) ----
    let mut files = profile.files.clone();
    files.sort_by(|a, b| a.target.cmp(&b.target));
    for f in &files {
        let desired = loaded.payload_hashes.get(&f.source).cloned();
        let obs = observed.files.get(&f.target);
        let managed = owned.contains(&("file".to_string(), f.target.clone()));
        match obs {
            None => conflicts.push(Conflict {
                target: f.target.clone(),
                code: "unknown_target".into(),
                message: format!("file {}: not observed", f.target),
            }),
            Some(o) => {
                if o.is_symlink {
                    operations.push(mk_op(
                        "files",
                        OperationKind::FileConflict,
                        &f.target,
                        format!("file {}: symlink at target (refusing)", f.target),
                        "high",
                        None,
                        desired.clone(),
                        RollbackSupport::Unsupported,
                    ));
                    conflicts.push(Conflict {
                        target: f.target.clone(),
                        code: "symlink_at_target".into(),
                        message: format!("file {}: target is a symlink; refusing", f.target),
                    });
                } else if o.is_non_regular {
                    operations.push(mk_op(
                        "files",
                        OperationKind::FileConflict,
                        &f.target,
                        format!("file {}: non-regular file at target", f.target),
                        "high",
                        None,
                        desired.clone(),
                        RollbackSupport::Unsupported,
                    ));
                    conflicts.push(Conflict {
                        target: f.target.clone(),
                        code: "non_regular_target".into(),
                        message: format!("file {}: non-regular file at target", f.target),
                    });
                } else if !o.exists {
                    operations.push(mk_op(
                        "files",
                        OperationKind::FileCreate,
                        &f.target,
                        format!("file {}: create from bundle", f.target),
                        "low",
                        None,
                        desired.clone(),
                        RollbackSupport::Supported,
                    ));
                } else if o.content_hash.as_ref() == desired.as_ref() && desired.is_some() {
                    // MATCH → no op (idempotency).
                } else if managed {
                    operations.push(mk_op(
                        "files",
                        OperationKind::FileUpdate,
                        &f.target,
                        format!("file {}: update managed file", f.target),
                        "medium",
                        o.content_hash.clone(),
                        desired.clone(),
                        RollbackSupport::Supported,
                    ));
                } else {
                    // Desired exists + target exists + not managed = CONFLICT.
                    operations.push(mk_op(
                        "files",
                        OperationKind::FileConflict,
                        &f.target,
                        format!(
                            "file {}: exists and is not managed (use --adopt to take ownership)",
                            f.target
                        ),
                        "high",
                        o.content_hash.clone(),
                        desired.clone(),
                        RollbackSupport::Unsupported,
                    ));
                    conflicts.push(Conflict {
                        target: f.target.clone(),
                        code: "unmanaged_exists".into(),
                        message: format!(
                            "file {} exists and is not managed (use --adopt to take ownership)",
                            f.target
                        ),
                    });
                }
            }
        }
    }

    // ---- Environment literals (rank 3) ----
    if let Some(env) = &profile.environment {
        let mut names: Vec<&String> = env.keys().collect();
        names.sort();
        for name in names {
            match &env[name.as_str()] {
                EnvLiteral::Value(lit) => {
                    let cur = observed.env_literals.get(name);
                    if cur != Some(lit) {
                        let mut details = BTreeMap::new();
                        details.insert("variable".into(), name.clone());
                        // Never store the literal value in details (values
                        // stay out of plan diffs where avoidable)... but the
                        // plan must record the desired state to execute. The
                        // desired literal lives in the profile bundle (user's
                        // own committed file), never duplicated here beyond
                        // the content hash. Apply re-reads the profile.
                        details.insert("desired_hash".into(), crate::hash::env_value_hash(lit));
                        let mut op = mk_op(
                            "env",
                            OperationKind::EnvironmentSchemaChange,
                            name,
                            format!("env {name}: set literal in managed env file"),
                            "low",
                            cur.map(|v| crate::hash::env_value_hash(v)),
                            Some(crate::hash::env_value_hash(lit)),
                            RollbackSupport::Supported,
                        );
                        op.details = details;
                        operations.push(op);
                    }
                }
                EnvLiteral::Secret { secret, required } => {
                    match observed.secret_exists.get(secret) {
                        Some(Some(true)) => {}
                        Some(Some(false)) | Some(None) | None => {
                            if *required {
                                conflicts.push(Conflict {
                                    target: secret.clone(),
                                    code: "missing_secret_ref".into(),
                                    message: format!(
                                        "plan is missing secret ref {secret} (variable {name})"
                                    ),
                                });
                                warnings.push(PlanWarning {
                                    code: "missing_secret".into(),
                                    message: format!("secret ref {secret} not found in backend"),
                                });
                            } else {
                                warnings.push(PlanWarning {
                                    code: "missing_optional_secret".into(),
                                    message: format!(
                                        "optional secret ref {secret} not found (variable {name})"
                                    ),
                                });
                            }
                            operations.push(mk_op(
                                "env",
                                OperationKind::Unsupported,
                                name,
                                format!("env {name}: secret-backed (reference {secret}; v1 validates existence only)"),
                                "low",
                                None,
                                None,
                                RollbackSupport::Unsupported,
                            ));
                        }
                    }
                }
            }
        }
    }

    // Manifest secret refs (existence only).
    if let Some(manifest) = &loaded.manifest {
        let mut refs: Vec<&crate::profile::SecretEntry> = manifest.secrets.iter().collect();
        refs.sort_by(|a, b| a.secret_ref.cmp(&b.secret_ref));
        for s in refs {
            match observed.secret_exists.get(&s.secret_ref) {
                Some(Some(true)) => {}
                _ => {
                    if s.required {
                        conflicts.push(Conflict {
                            target: s.secret_ref.clone(),
                            code: "missing_secret_ref".into(),
                            message: format!("plan is missing secret ref {}", s.secret_ref),
                        });
                    } else {
                        warnings.push(PlanWarning {
                            code: "missing_optional_secret".into(),
                            message: format!("optional secret ref {} not found", s.secret_ref),
                        });
                    }
                }
            }
        }
    }

    // ---- Services (rank 4) ----
    let mut services = profile.services.clone();
    services.sort_by(|a, b| a.name.cmp(&b.name));
    for s in &services {
        // v1.1: system-scope units are recorded, never driven. Known states
        // resolve to enable/disable intent classified PRIVILEGED (the
        // refinement pass below; apply refuses them). Unknown states stay
        // Unsupported with an explicit message.
        if s.scope.as_deref() == Some("system") {
            let known_differs = matches!(
                observed.services.get(&s.name),
                Some(o) if !o.unknown && s.enabled.is_some() && o.enabled != s.enabled
            );
            if known_differs {
                let want_enabled = s.enabled.unwrap_or(false);
                operations.push(mk_op(
                    "systemd",
                    if want_enabled {
                        OperationKind::ServiceEnable
                    } else {
                        OperationKind::ServiceDisable
                    },
                    &s.name,
                    format!(
                        "service {}: {} (system scope; requires privilege)",
                        s.name,
                        if want_enabled { "enable" } else { "disable" }
                    ),
                    "high",
                    None,
                    None,
                    RollbackSupport::Unsupported,
                ));
            } else {
                operations.push(mk_op(
                    "systemd",
                    OperationKind::Unsupported,
                    &s.name,
                    format!(
                        "service {}: system scope (privileged; recorded only, apply refuses)",
                        s.name
                    ),
                    "low",
                    None,
                    None,
                    RollbackSupport::Unsupported,
                ));
            }
            continue;
        }
        if observed.services_unavailable {
            operations.push(mk_op(
                "systemd",
                OperationKind::Unsupported,
                &s.name,
                format!("service {}: user manager unavailable", s.name),
                "low",
                None,
                None,
                RollbackSupport::Unsupported,
            ));
            warnings.push(PlanWarning {
                code: "services_unavailable".into(),
                message: format!("service {}: systemd user manager unavailable", s.name),
            });
            continue;
        }
        match observed.services.get(&s.name) {
            None | Some(crate::observe::ServiceObs { unknown: true, .. }) => {
                operations.push(mk_op(
                    "systemd",
                    OperationKind::Unsupported,
                    &s.name,
                    format!("service {}: state unknown", s.name),
                    "low",
                    None,
                    None,
                    RollbackSupport::Unsupported,
                ));
            }
            Some(o) => {
                if let Some(want_enabled) = s.enabled {
                    if o.enabled != Some(want_enabled) {
                        let mut op = mk_op(
                            "systemd",
                            if want_enabled {
                                OperationKind::ServiceEnable
                            } else {
                                OperationKind::ServiceDisable
                            },
                            &s.name,
                            format!(
                                "service {}: {}",
                                s.name,
                                if want_enabled { "enable" } else { "disable" }
                            ),
                            "medium",
                            None,
                            None,
                            RollbackSupport::Partial,
                        );
                        op.details.insert("scope".into(), "enabled".into());
                        operations.push(op);
                    }
                }
                if let Some(want_running) = s.running {
                    if o.running != Some(want_running) {
                        warnings.push(PlanWarning {
                            code: "service_running_state".into(),
                            message: format!(
                                "service {}: running state differs (plan records intent; apply manages enable/disable only)",
                                s.name
                            ),
                        });
                        let mut op = mk_op(
                            "systemd",
                            if want_running {
                                OperationKind::ServiceEnable
                            } else {
                                OperationKind::ServiceDisable
                            },
                            &s.name,
                            format!(
                                "service {}: {} (running state)",
                                s.name,
                                if want_running { "start" } else { "stop" }
                            ),
                            "medium",
                            None,
                            None,
                            RollbackSupport::Partial,
                        );
                        op.details.insert("scope".into(), "running".into());
                        operations.push(op);
                    }
                }
            }
        }
    }

    // ---- Git (rank 5) ----
    if let Some(g) = &profile.git {
        if observed.git_unavailable {
            warnings.push(PlanWarning {
                code: "git_unavailable".into(),
                message: "git unavailable; git configuration marked unknown".into(),
            });
            operations.push(mk_op(
                "git",
                OperationKind::Unsupported,
                "gitconfig",
                "git config: provider unavailable".into(),
                "low",
                None,
                None,
                RollbackSupport::Unsupported,
            ));
        } else {
            if g.user_name.as_deref() != observed.git_user_name.as_deref() && g.user_name.is_some()
            {
                operations.push(mk_op(
                    "git",
                    OperationKind::GitConfigChange,
                    "user.name",
                    "git user.name: update".into(),
                    "low",
                    None,
                    None,
                    RollbackSupport::Supported,
                ));
            }
            if g.user_email.as_deref() != observed.git_user_email.as_deref()
                && g.user_email.is_some()
            {
                operations.push(mk_op(
                    "git",
                    OperationKind::GitConfigChange,
                    "user.email",
                    "git user.email: update".into(),
                    "low",
                    None,
                    None,
                    RollbackSupport::Supported,
                ));
            }
        }
    }

    // v1.1 execution policy refinement (deterministic function of profile
    // content — runs before sorting/hashing so classes are stable).
    //
    // - System-scope services (v2 profiles) are PRIVILEGED: recorded in the
    //   plan, never executed without privilege. User-scope stays
    //   SAFE_REPRODUCE (v1 behavior preserved).
    // - Secret-backed env operations are SECRET_REQUIRED: the value must
    //   come from the backend at apply time, never from the profile.
    {
        let scopes: BTreeMap<&str, &str> = profile
            .services
            .iter()
            .map(|s| (s.name.as_str(), s.scope.as_deref().unwrap_or("user")))
            .collect();
        for op in operations.iter_mut() {
            if op.provider == "systemd"
                && matches!(
                    op.kind,
                    OperationKind::ServiceEnable | OperationKind::ServiceDisable
                )
                && scopes.get(op.target.as_str()).copied().unwrap_or("user") == "system"
            {
                op.action_class = PlanActionClass::Privileged;
            }
            if op.provider == "env"
                && op.kind == OperationKind::Unsupported
                && op.summary.contains("secret-backed")
            {
                op.action_class = PlanActionClass::SecretRequired;
            }
        }
    }

    // Deterministic sort: (provider_rank, target, kind).
    operations.sort_by(|a, b| {
        (provider_rank(&a.provider), &a.target, kind_rank(&a.kind)).cmp(&(
            provider_rank(&b.provider),
            &b.target,
            kind_rank(&b.kind),
        ))
    });
    // Stable ids after sorting.
    for (i, op) in operations.iter_mut().enumerate() {
        op.id = format!("op-{:04}", i + 1);
    }
    warnings.sort_by(|a, b| (&a.code, &a.message).cmp(&(&b.code, &b.message)));
    conflicts.sort_by(|a, b| (&a.target, &a.code).cmp(&(&b.target, &b.code)));

    // If nothing to do, record an explicit NoOp (idempotency signal).
    if operations.is_empty() {
        operations.push(mk_op(
            "core",
            OperationKind::NoOp,
            "noop",
            "no changes required".into(),
            "low",
            None,
            None,
            RollbackSupport::Supported,
        ));
        operations[0].id = "op-0001".into();
    }

    let observed_fp = crate::observe::fingerprint(observed);
    let mut plan = Plan {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id: plan_id.to_string(),
        profile_identity: loaded.identity.clone(),
        profile_hash: loaded.profile_hash.clone(),
        observed_state_fingerprint: observed_fp,
        created_at,
        operations,
        warnings,
        conflicts,
        plan_hash: String::new(),
    };
    plan.plan_hash = compute_plan_hash(&plan);
    plan
}

/// Semantic plan hash: canonical JSON over profile hash, observed fingerprint,
/// operations (sorted), warnings, conflicts. Excludes `plan_id`/`created_at`.
pub fn compute_plan_hash(plan: &Plan) -> String {
    let doc = serde_json::json!({
        "schema_version": PLAN_SCHEMA_VERSION,
        "profile_hash": plan.profile_hash,
        "observed_state_fingerprint": plan.observed_state_fingerprint,
        "operations": plan.operations.iter().map(|o| serde_json::json!({
            "provider": o.provider,
            "kind": format!("{:?}", o.kind),
            "target": o.target,
            "summary": o.summary,
            "risk": o.risk,
            "expected_before": o.expected_before,
            "desired_after": o.desired_after,
            "rollback": format!("{:?}", o.rollback),
            "class": o.action_class.as_str(),
            "details": o.details,
        })).collect::<Vec<_>>(),
        "warnings": plan.warnings,
        "conflicts": plan.conflicts,
    });
    crate::hash::sha256_str(&serde_json::to_string(&doc).unwrap_or_default())
}

/// True when the plan would mutate anything.
pub fn is_noop(plan: &Plan) -> bool {
    plan.operations.len() == 1 && plan.operations[0].kind == OperationKind::NoOp
}

/// Mutating operations only (excludes NoOp/Unsupported/conflict markers that
/// apply must refuse or skip).
pub fn executable_ops(plan: &Plan) -> Vec<&Operation> {
    plan.operations
        .iter()
        .filter(|o| {
            matches!(
                o.kind,
                OperationKind::PackageInstall
                    | OperationKind::FileCreate
                    | OperationKind::FileUpdate
                    | OperationKind::EnvironmentSchemaChange
                    | OperationKind::EnvFileWrite
                    | OperationKind::IncludeLineAdd
                    | OperationKind::ServiceEnable
                    | OperationKind::ServiceDisable
                    | OperationKind::GitConfigChange
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn mk_op(
    provider: &str,
    kind: OperationKind,
    target: &str,
    summary: String,
    risk: &str,
    expected_before: Option<String>,
    desired_after: Option<String>,
    rollback: RollbackSupport,
) -> Operation {
    Operation {
        id: String::new(),
        provider: provider.into(),
        kind: kind.clone(),
        target: target.into(),
        summary,
        risk: risk.into(),
        expected_before,
        desired_after,
        rollback,
        action_class: class_for_kind(&kind),
        details: BTreeMap::new(),
    }
}

/// Execution order: packages → files → env → services → git → core.
fn provider_rank(p: &str) -> u8 {
    match p {
        "apt" => 1,
        "files" => 2,
        "env" => 3,
        "systemd" => 4,
        "git" => 5,
        _ => 9,
    }
}

fn kind_rank(k: &OperationKind) -> u8 {
    match k {
        OperationKind::PackageInstall => 1,
        OperationKind::PackageVersionMismatch => 2,
        OperationKind::FileCreate => 3,
        OperationKind::FileUpdate => 4,
        OperationKind::FileConflict => 5,
        OperationKind::EnvironmentSchemaChange => 6,
        OperationKind::EnvFileWrite => 7,
        OperationKind::IncludeLineAdd => 8,
        OperationKind::ServiceEnable => 9,
        OperationKind::ServiceDisable => 10,
        OperationKind::GitConfigChange => 11,
        OperationKind::NoOp => 12,
        OperationKind::Unsupported => 13,
    }
}

// ---------------------------------------------------------------------------
// v1.2 env consolidation plan (E2)
// ---------------------------------------------------------------------------

/// Provider label for the managed shell env artifacts.
pub const ENVFILE_PROVIDER: &str = "envfile";

/// One participating shell startup file and its current content.
#[derive(Debug, Clone)]
pub struct RcTarget {
    /// `~/...` locator.
    pub target: String,
    /// Current file content; `None` when the file does not exist yet.
    pub current: Option<Vec<u8>>,
}

/// The `NAME=VALUE` pairs the canonical managed env file should contain:
/// every non-secret literal in the profile's `[environment]` section.
///
/// Secret entries (`secret://…` references) are never written to the
/// canonical file — they stay references.
pub fn canonical_env_entries(loaded: &LoadedProfile) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = loaded
        .profile
        .environment
        .as_ref()
        .map(|env| {
            env.iter()
                .filter_map(|(k, v)| match v {
                    EnvLiteral::Value(lit) => Some((k.clone(), lit.clone())),
                    EnvLiteral::Secret { .. } => None,
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Build the v1.2 env-consolidation plan: one `EnvFileWrite` for the canonical
/// managed shell env file plus one `IncludeLineAdd` per participating rc file.
///
/// Deterministic and pure. `canonical_current` / `RcTarget::current` are the
/// bytes observed at plan time; they become the `expected_before` guards that
/// make apply refuse a stale plan (TOCTOU).
///
/// A file that already carries the marker block is a no-op (idempotency). A
/// file carrying a foreign or partial marker block is a blocking conflict:
/// configctl refuses rather than guessing how to merge it.
pub fn build_env_consolidation_plan(
    loaded: &LoadedProfile,
    rc_files: &[RcTarget],
    canonical_current: Option<&[u8]>,
    envd_current: Option<&BTreeMap<String, String>>,
    warnings: Vec<PlanWarning>,
    plan_id: &str,
    created_at: i64,
) -> Plan {
    let mut operations: Vec<Operation> = Vec::new();
    let mut warnings = warnings;
    let mut conflicts: Vec<Conflict> = Vec::new();

    let entries = canonical_env_entries(loaded);
    if entries.is_empty() {
        warnings.push(PlanWarning {
            code: "no_environment".into(),
            message: "profile has no [environment] literals to consolidate".into(),
        });
    } else {
        let desired = crate::envmap::canonical_env_file(&entries);
        let desired_hash = crate::hash::file_content_hash(desired.as_bytes());
        let expected_before = canonical_current
            .map(crate::hash::file_content_hash)
            .filter(|h| *h != desired_hash);
        if expected_before.is_some() || canonical_current.is_none() {
            operations.push(mk_op(
                ENVFILE_PROVIDER,
                OperationKind::EnvFileWrite,
                &format!("~/{}", crate::envmap::CANONICAL_REL),
                format!(
                    "env file: manage {} setting(s) in the canonical shell env file",
                    entries.len()
                ),
                "medium",
                expected_before,
                Some(desired_hash),
                RollbackSupport::Supported,
            ));
        }

        // Keep the session/services artifact in sync from the same profile
        // data: one `EnvironmentSchemaChange` per differing literal. This is
        // the existing v1.0 mechanism for
        // `~/.config/environment.d/90-configctl.conf`, emitted here so both
        // env artifacts land in one plan and `verify` passes for both.
        for (name, lit) in &entries {
            let cur = envd_current.and_then(|m| m.get(name));
            if cur.map(|v| v.as_str()) == Some(lit.as_str()) {
                continue;
            }
            let mut details = BTreeMap::new();
            details.insert("variable".into(), name.clone());
            details.insert("desired_hash".into(), crate::hash::env_value_hash(lit));
            let mut op = mk_op(
                "env",
                OperationKind::EnvironmentSchemaChange,
                name,
                format!("env {name}: set literal in managed env file"),
                "low",
                cur.map(|v| crate::hash::env_value_hash(v)),
                Some(crate::hash::env_value_hash(lit)),
                RollbackSupport::Supported,
            );
            op.details = details;
            operations.push(op);
        }
    }

    let mut sorted: Vec<&RcTarget> = rc_files.iter().collect();
    sorted.sort_by(|a, b| a.target.cmp(&b.target));
    for rc in sorted {
        let current_str = rc
            .current
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        if crate::envmap::has_include_block(&current_str) {
            // Idempotent: an existing (even partial) marker block is never
            // rewritten behind the user's back.
            continue;
        }
        let updated = crate::envmap::ensure_include_block(&current_str);
        operations.push(mk_op(
            ENVFILE_PROVIDER,
            OperationKind::IncludeLineAdd,
            &rc.target,
            format!(
                "shell startup: read the managed env file from {}",
                rc.target
            ),
            "medium",
            rc.current
                .as_ref()
                .map(|b| crate::hash::file_content_hash(b.as_slice())),
            Some(crate::hash::file_content_hash(updated.as_bytes())),
            RollbackSupport::Supported,
        ));
    }

    operations.sort_by(|a, b| {
        (provider_rank(&a.provider), &a.target, kind_rank(&a.kind)).cmp(&(
            provider_rank(&b.provider),
            &b.target,
            kind_rank(&b.kind),
        ))
    });
    for (i, op) in operations.iter_mut().enumerate() {
        op.id = format!("op-{:04}", i + 1);
    }
    warnings.sort_by(|a, b| (&a.code, &a.message).cmp(&(&b.code, &b.message)));
    conflicts.sort_by(|a, b| (&a.target, &a.code).cmp(&(&b.target, &b.code)));

    if operations.is_empty() {
        operations.push(mk_op(
            "core",
            OperationKind::NoOp,
            "noop",
            "no changes required".into(),
            "low",
            None,
            None,
            RollbackSupport::Supported,
        ));
        operations[0].id = "op-0001".into();
    }

    let mut plan = Plan {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id: plan_id.to_string(),
        profile_identity: loaded.identity.clone(),
        profile_hash: loaded.profile_hash.clone(),
        // Env-consolidation plans are guarded per-operation by
        // `expected_before` (the exact bytes observed at plan time), so the
        // plan-level observed fingerprint is the composition of those guards
        // rather than a whole-machine snapshot.
        observed_state_fingerprint: crate::hash::sha256_str(
            &operations
                .iter()
                .map(|o| {
                    format!(
                        "{}|{}|{}",
                        o.target,
                        o.expected_before.clone().unwrap_or_default(),
                        o.desired_after.clone().unwrap_or_default()
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        created_at,
        operations,
        warnings,
        conflicts,
        plan_hash: String::new(),
    };
    plan.plan_hash = compute_plan_hash(&plan);
    plan
}
