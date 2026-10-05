//! Journaled apply engine (P4) — the first milestone allowed to mutate.
//!
//! Protocol per operation:
//!
//! ```text
//! INTENT → PRECHECK → BACKUP → EXECUTE → POSTCHECK → DONE
//! ```
//!
//! Rules:
//! - Executes exactly the persisted approved plan; never re-plans.
//! - Fail-stop: the first failure marks the plan `partial` and stops.
//! - Every mutating file write is atomic (temp + fsync + rename) with a
//!   content-addressed backup taken first.
//! - Global mutation lock held for the whole run.
//! - `PackageInstall` uses per-manager fixed argv (`sudo -n apt-get
//!   install -y <name>`, `sudo -n dnf install -y <name>`,
//!   `sudo -n pacman -S --noconfirm <name>`, `sudo -n apk add <name>`);
//!   privilege failure fails safely (exit 8 class) without faking success.
//! - `systemd --user` only; never system scope.
//! - Test-only crash simulation via `CONFIGCTL_FAIL_AFTER=<op-id>:<PHASE>`
//!   (journal the phase, then return without further writes — the persisted
//!   journal is what recovery classifies in P7).

use crate::command::{CommandRequest, CommandRunner};
use crate::observe;
use crate::plan::{Operation, OperationKind, Plan};
use crate::profile::EnvLiteral;
use crate::profile_load::LoadedProfile;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Journal phase names.
pub const PH_INTENT: &str = "INTENT";
pub const PH_PRECHECK: &str = "PRECHECK";
pub const PH_BACKUP: &str = "BACKUP";
pub const PH_EXECUTE: &str = "EXECUTE";
pub const PH_POSTCHECK: &str = "POSTCHECK";
pub const PH_DONE: &str = "DONE";
pub const PH_FAILED: &str = "FAILED";

/// Managed env file (owned by configctl; the only env file ever written).
pub const MANAGED_ENV_REL: &str = ".config/environment.d/90-configctl.conf";

/// Options for one apply run.
#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    /// Non-interactive approval for the current plan only.
    pub yes: bool,
    /// Preview without writing.
    pub dry_run: bool,
    /// Unmanaged targets to adopt (must be plan conflicts).
    pub adopt: Vec<String>,
}

/// One executed operation outcome.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OpOutcome {
    pub op_id: String,
    pub target: String,
    pub kind: String,
    pub result: String,
    pub backup_sha: Option<String>,
}

/// Full apply report.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ApplyReport {
    pub plan_id: String,
    pub executed: Vec<OpOutcome>,
    pub noop: Vec<String>,
    pub dry_run: bool,
}

/// Apply failure classes (mapped to exit codes by the CLI).
#[derive(Debug, Clone)]
pub enum ApplyError {
    /// Exit 2: usage/config (bad id, profile-looking arg, unknown adopt...).
    Usage(String),
    /// Exit 4: user declined approval.
    Declined(String),
    /// Exit 5: conflict/unsafe/stale/locked/partial.
    Conflict(String),
    /// Exit 7: provider unavailable mid-apply.
    ProviderUnavailable(String),
    /// Exit 8: privilege missing.
    Privilege(String),
    /// Exit 1: an operation failed (plan marked `partial`).
    OpFailed {
        op_id: String,
        target: String,
        message: String,
    },
    /// Test-only crash simulation: journal already records the phase; the
    /// caller must exit immediately without further writes.
    CrashSimulated { op_id: String, phase: String },
    /// Exit 1: unexpected internal error.
    Internal(String),
}

/// Execute a persisted plan.
///
/// `approve` is called when the plan needs interactive approval (status
/// `planned` and `!opts.yes`); it returns true when the user approves.
pub fn apply_plan(
    state_dir: &Path,
    plan_id: &str,
    home: &Path,
    runner: &dyn CommandRunner,
    opts: &ApplyOptions,
    approve: &dyn Fn(&Plan) -> bool,
) -> Result<ApplyReport, ApplyError> {
    // 1. Load + verify hash (fail closed on tampering).
    let (plan, status, bundle_dir) =
        crate::state::load_plan(state_dir, plan_id).map_err(|e| match e {
            crate::state::PlanLoadError::Unavailable(_) => ApplyError::Internal(e.to_string()),
            crate::state::PlanLoadError::Invalid(_) => ApplyError::Usage(e.to_string()),
            _ => ApplyError::Conflict(e.to_string()),
        })?;

    // 2. Execution-state gate.
    match status.as_str() {
        "planned" | "approved" => {}
        "applying" => {
            // Explicit re-run after an interruption that wrote nothing
            // (journal has no BACKUP/EXECUTE/POSTCHECK/DONE/FAILED): allow it
            // — prechecks still guard every op. Anything else needs rollback.
            if !crate::rollback::journal_shows_no_mutation(state_dir, plan_id) {
                return Err(ApplyError::Conflict(format!(
                    "plan {plan_id} has an unfinished journal; run `configctl doctor` and recover explicitly"
                )));
            }
        }
        "partial" => {
            return Err(ApplyError::Conflict(format!(
                "plan {plan_id} is partial; recover with `configctl rollback` or `configctl doctor`"
            )));
        }
        "applied" => {
            return Err(ApplyError::Conflict(format!(
                "plan {plan_id} is already applied"
            )));
        }
        "rolled_back" => {
            return Err(ApplyError::Conflict(format!(
                "plan {plan_id} was rolled back; create a new plan"
            )));
        }
        other => {
            return Err(ApplyError::Internal(format!(
                "plan {plan_id} has unknown status {other:?}"
            )));
        }
    }

    // 3. Conflict gate (+ adoption).
    let adopt: BTreeSet<String> = opts.adopt.iter().cloned().collect();
    for c in &plan.conflicts {
        match c.code.as_str() {
            "unmanaged_exists" => {
                if !adopt.contains(&c.target) {
                    return Err(ApplyError::Conflict(format!(
                        "plan has ownership conflicts (e.g. {}); re-run with --adopt <TARGET> or resolve manually",
                        c.target
                    )));
                }
            }
            _ => {
                return Err(ApplyError::Conflict(format!(
                    "plan has blocking conflict on {}: {}",
                    c.target, c.message
                )));
            }
        }
    }
    // --adopt targets must all be plan conflicts (no silent extras).
    for a in &adopt {
        if !plan
            .conflicts
            .iter()
            .any(|c| &c.target == a && c.code == "unmanaged_exists")
        {
            return Err(ApplyError::Usage(format!(
                "--adopt {a:?} is not a conflict in this plan"
            )));
        }
    }

    // 4. Reload the bundle and bind to the exact profile hash (stale guard).
    if bundle_dir.as_os_str().is_empty() {
        return Err(ApplyError::Internal(
            "plan lacks a bundle reference; re-run `configctl plan`".into(),
        ));
    }
    let loaded = crate::profile_load::load_profile_dir(&bundle_dir).map_err(|e| {
        ApplyError::Conflict(format!(
            "profile changed since planning ({e}); re-run `configctl plan`"
        ))
    })?;
    if loaded.profile_hash != plan.profile_hash {
        return Err(ApplyError::Conflict(
            "profile changed since planning (hash mismatch); re-run `configctl plan`".to_string(),
        ));
    }

    // 5. Dry-run: preview only. Dry-run never prompts and never writes, so
    //    approval is not required (CLI_SPEC §1.2/§2.6); the stale/tampered
    //    plan checks above still apply.
    if opts.dry_run {
        let mut report = ApplyReport {
            plan_id: plan_id.into(),
            dry_run: true,
            ..Default::default()
        };
        for op in crate::plan::executable_ops(&plan) {
            report.executed.push(OpOutcome {
                op_id: op.id.clone(),
                target: op.target.clone(),
                kind: format!("{:?}", op.kind),
                result: "would-execute".into(),
                backup_sha: None,
            });
        }
        if crate::plan::is_noop(&plan) {
            report.noop.push("noop".into());
        }
        return Ok(report);
    }

    // 6. Approval (bound to this exact plan hash — verified above).
    if status != "approved" && !opts.yes && !approve(&plan) {
        return Err(ApplyError::Declined(
            "approval declined; no changes made".into(),
        ));
    }

    // 7. Record approval + global lock + applying state.
    if status == "planned" {
        crate::state::approve_plan(state_dir, plan_id, crate::state::now_secs())
            .map_err(ApplyError::Internal)?;
    }
    let _lock = crate::lock::acquire(state_dir).map_err(ApplyError::Conflict)?;
    crate::state::set_plan_status(state_dir, plan_id, crate::state::STATUS_APPLYING)
        .map_err(ApplyError::Internal)?;

    // 8. Execute in plan order (already deterministic).
    let mut report = ApplyReport {
        plan_id: plan_id.into(),
        ..Default::default()
    };
    // Adopted FileConflict ops execute as updates.
    let mut ops: Vec<Operation> = Vec::new();
    for op in &plan.operations {
        if op.kind == OperationKind::FileConflict && adopt.contains(&op.target) {
            let mut adopted = op.clone();
            adopted.kind = OperationKind::FileUpdate;
            adopted.action_class = crate::classify::PlanActionClass::SafeReproduce;
            adopted.summary = format!("file {}: adopt + update (ownership taken)", op.target);
            ops.push(adopted);
        } else {
            ops.push(op.clone());
        }
    }

    for op in &ops {
        match execute_op(state_dir, plan_id, &plan, &loaded, home, runner, op, &adopt) {
            Ok(Some(outcome)) => {
                if outcome.result == "noop" {
                    report.noop.push(outcome.op_id.clone());
                } else {
                    report.executed.push(outcome);
                }
            }
            Ok(None) => {}
            Err(e @ ApplyError::CrashSimulated { .. }) => {
                // Simulated crash: journal already records the phase; mark
                // nothing further and propagate immediately.
                let _ = crate::state::record_history(
                    state_dir,
                    Some(plan_id),
                    None,
                    "apply",
                    "crashed",
                    None,
                    crate::state::now_secs(),
                );
                return Err(e);
            }
            Err(ApplyError::OpFailed {
                op_id,
                target,
                message,
            }) => {
                let _ =
                    crate::state::set_plan_status(state_dir, plan_id, crate::state::STATUS_PARTIAL);
                let _ = crate::state::record_history(
                    state_dir,
                    Some(plan_id),
                    Some(&op_id),
                    "apply",
                    "failed",
                    Some(&message),
                    crate::state::now_secs(),
                );
                return Err(ApplyError::OpFailed {
                    op_id,
                    target,
                    message,
                });
            }
            Err(e) => {
                // Refusal before any op touched its target (e.g. the stale /
                // TOCTOU precheck, an ownership refusal, or a symlink
                // refusal): the machine is exactly as before, so the plan
                // returns to `approved` — a phantom `partial` would send the
                // user into the recovery flow for nothing. Any executed op or
                // write-phase journal entry keeps `partial`.
                let mutated = !report.executed.is_empty()
                    || !crate::rollback::journal_shows_no_target_mutation(state_dir, plan_id);
                let _ = crate::state::set_plan_status(
                    state_dir,
                    plan_id,
                    if mutated {
                        crate::state::STATUS_PARTIAL
                    } else {
                        crate::state::STATUS_APPROVED
                    },
                );
                return Err(e);
            }
        }
    }

    crate::state::set_plan_status(state_dir, plan_id, crate::state::STATUS_APPLIED)
        .map_err(ApplyError::Internal)?;
    let _ = crate::state::record_history(
        state_dir,
        Some(plan_id),
        None,
        "apply",
        "applied",
        None,
        crate::state::now_secs(),
    );
    Ok(report)
}

/// Execute one operation with full journaling. Returns `Ok(None)` for
/// Refusal reason for an execution policy class, if the class must never
/// execute in this apply path. `None` means the kind dispatch decides.
pub fn refusal_for_class(class: crate::classify::PlanActionClass) -> Option<&'static str> {
    match class {
        crate::classify::PlanActionClass::Privileged => {
            Some("refused PRIVILEGED: requires privilege (system scope)")
        }
        crate::classify::PlanActionClass::Destructive => Some("refused DESTRUCTIVE"),
        crate::classify::PlanActionClass::Unsupported => Some("refused UNSUPPORTED"),
        _ => None,
    }
}

/// non-executable ops (NoOp/Unsupported/mismatch markers are skipped —
/// Unsupported package/service states were already surfaced at plan time).
#[allow(clippy::too_many_arguments)]
fn execute_op(
    state_dir: &Path,
    plan_id: &str,
    plan: &Plan,
    loaded: &LoadedProfile,
    home: &Path,
    runner: &dyn CommandRunner,
    op: &Operation,
    adopt: &BTreeSet<String>,
) -> Result<Option<OpOutcome>, ApplyError> {
    let now = crate::state::now_secs;
    let journal = |phase: &str, backup: Option<&str>, detail: Option<&str>| {
        crate::state::journal(state_dir, plan_id, &op.id, phase, backup, detail, now())
    };
    let failpoint = |phase: &str| -> Result<(), ApplyError> {
        if let Ok(fp) = std::env::var("CONFIGCTL_FAIL_AFTER") {
            if fp == format!("{}:{phase}", op.id) {
                return Err(ApplyError::CrashSimulated {
                    op_id: op.id.clone(),
                    phase: phase.into(),
                });
            }
        }
        Ok(())
    };

    // v1.1 execution policy gate (before kind dispatch): hardcore
    // discovery never means blind execution. Privileged, destructive, and
    // unsupported-class operations are refused here even when their kind
    // would otherwise dispatch (defense in depth against hostile or
    // hand-edited plans). Old plans without the field default to
    // SAFE_REPRODUCE, preserving v1 behavior exactly.
    if let Some(reason) = refusal_for_class(op.action_class) {
        journal(PH_INTENT, None, Some(reason)).map_err(ApplyError::Internal)?;
        return Ok(None);
    }

    match op.kind {
        OperationKind::NoOp
        | OperationKind::Unsupported
        | OperationKind::PackageVersionMismatch
        | OperationKind::FileConflict => Ok(None),
        OperationKind::PackageInstall => {
            journal(PH_INTENT, None, Some(&format!("install {}", op.target)))
                .map_err(ApplyError::Internal)?;
            failpoint(PH_INTENT)?;
            // Provider dispatch (static registry: apt | dnf | pacman | apk).
            // Anything else fails closed — a hand-edited plan cannot steer
            // fixed argv at an unexpected binary.
            let install_req = match op.provider.as_str() {
                "apt" => CommandRequest::new(
                    "sudo",
                    ["-n", "apt-get", "install", "-y", op.target.as_str()],
                )
                .output_cap(128 * 1024),
                "dnf" => crate::package_managers::DnfProvider::install_request(&op.target),
                "pacman" => crate::package_managers::PacmanProvider::install_request(&op.target),
                "apk" => crate::package_managers::ApkProvider::install_request(&op.target),
                other => {
                    journal(PH_FAILED, None, Some("unknown package manager"))
                        .map_err(ApplyError::Internal)?;
                    return Err(ApplyError::ProviderUnavailable(format!(
                        "package manager {other:?} unavailable"
                    )));
                }
            };
            // PRECHECK: already installed → noop.
            if is_package_installed(runner, &op.provider, &op.target) {
                journal(PH_PRECHECK, None, Some("already installed; noop"))
                    .map_err(ApplyError::Internal)?;
                journal(PH_DONE, None, Some("noop")).map_err(ApplyError::Internal)?;
                return Ok(Some(OpOutcome {
                    op_id: op.id.clone(),
                    target: op.target.clone(),
                    kind: format!("{:?}", op.kind),
                    result: "noop".into(),
                    backup_sha: None,
                }));
            }
            journal(PH_PRECHECK, None, Some("not installed")).map_err(ApplyError::Internal)?;
            failpoint(PH_PRECHECK)?;
            journal(
                PH_BACKUP,
                None,
                Some("packages have no backup; report-only rollback"),
            )
            .map_err(ApplyError::Internal)?;
            // EXECUTE: sudo -n <manager> install (fixed argv, per-provider).
            let out = runner.run(&install_req).map_err(|_| {
                ApplyError::ProviderUnavailable("package manager unavailable".into())
            })?;
            journal(
                PH_EXECUTE,
                None,
                out.status.map(|s| s.to_string()).as_deref(),
            )
            .map_err(ApplyError::Internal)?;
            failpoint(PH_EXECUTE)?;
            // Provider word for failure records (apt strings unchanged).
            let install_word = match op.provider.as_str() {
                "dnf" => "dnf install",
                "pacman" => "pacman install",
                "apk" => "apk add",
                _ => "apt install",
            };
            if out.status != Some(0) {
                journal(PH_FAILED, None, Some(&format!("{install_word} failed")))
                    .map_err(ApplyError::Internal)?;
                let msg = format!("{install_word} {} failed", op.target);
                if out.stderr.contains("a password is required")
                    || out.stderr.contains("no tty present")
                    || out.stderr.contains("sudo:")
                {
                    return Err(ApplyError::Privilege(format!(
                        "{msg}: sudo -n unavailable (no cached credentials); run with privileges and retry"
                    )));
                }
                return Err(ApplyError::OpFailed {
                    op_id: op.id.clone(),
                    target: op.target.clone(),
                    message: msg,
                });
            }
            // POSTCHECK.
            if !is_package_installed(runner, &op.provider, &op.target) {
                journal(PH_FAILED, None, Some("postcheck: not installed"))
                    .map_err(ApplyError::Internal)?;
                return Err(ApplyError::OpFailed {
                    op_id: op.id.clone(),
                    target: op.target.clone(),
                    message: format!("postcheck: {} still not installed", op.target),
                });
            }
            journal(PH_POSTCHECK, None, Some("installed")).map_err(ApplyError::Internal)?;
            journal(PH_DONE, None, Some("ok")).map_err(ApplyError::Internal)?;
            failpoint(PH_DONE)?;
            let _ = crate::state::record_owned(
                state_dir,
                "package",
                &op.target,
                &plan.profile_identity,
                None,
                now(),
            );
            Ok(Some(OpOutcome {
                op_id: op.id.clone(),
                target: op.target.clone(),
                kind: format!("{:?}", op.kind),
                result: "ok".into(),
                backup_sha: None,
            }))
        }
        OperationKind::FileCreate | OperationKind::FileUpdate => execute_file_op(
            state_dir, plan_id, plan, loaded, home, op, adopt, &journal, &failpoint,
        ),
        OperationKind::EnvironmentSchemaChange => execute_env_op(
            state_dir, plan_id, plan, loaded, home, op, &journal, &failpoint,
        ),
        OperationKind::EnvFileWrite => execute_env_file_write(
            state_dir, plan_id, plan, loaded, home, op, &journal, &failpoint,
        ),
        OperationKind::IncludeLineAdd => {
            execute_include_line_op(state_dir, plan_id, plan, home, op, &journal, &failpoint)
        }
        OperationKind::ServiceEnable | OperationKind::ServiceDisable => {
            execute_service_op(state_dir, plan_id, plan, runner, op, &journal, &failpoint)
        }
        OperationKind::GitConfigChange => execute_git_op(
            state_dir, plan_id, plan, loaded, runner, op, &journal, &failpoint,
        ),
    }
}

type JournalFn<'a> = &'a dyn Fn(&str, Option<&str>, Option<&str>) -> Result<(), String>;
type FailFn<'a> = &'a dyn Fn(&str) -> Result<(), ApplyError>;

/// File apply: validate → lstat → ownership → precheck → backup → atomic
/// write → verify → DONE. Never truncates the destination directly.
#[allow(clippy::too_many_arguments)]
fn execute_file_op(
    state_dir: &Path,
    plan_id: &str,
    plan: &Plan,
    loaded: &LoadedProfile,
    home: &Path,
    op: &Operation,
    adopt: &BTreeSet<String>,
    journal: JournalFn,
    failpoint: FailFn,
) -> Result<Option<OpOutcome>, ApplyError> {
    journal(PH_INTENT, None, Some(&op.summary)).map_err(ApplyError::Internal)?;
    failpoint(PH_INTENT)?;

    // Resolve target (fail closed on invalid).
    crate::paths::validate_file_target(&op.target).map_err(ApplyError::Conflict)?;
    let abs: PathBuf = observe::expand_target(&op.target, home)
        .ok_or_else(|| ApplyError::Conflict(format!("invalid target {:?}", op.target)))?;
    // Refuse symlinked parent components (symlink-swap guard for creates;
    // updates re-check immediately before write as well).
    if has_symlink_parent(&abs) {
        journal(PH_FAILED, None, Some("symlink parent")).map_err(ApplyError::Internal)?;
        return Err(ApplyError::Conflict(format!(
            "file {}: a parent directory is a symlink; refusing",
            op.target
        )));
    }

    // Payload bytes from the bundle.
    let entry = loaded
        .profile
        .files
        .iter()
        .find(|f| f.target == op.target)
        .ok_or_else(|| ApplyError::Internal(format!("no profile entry for {}", op.target)))?;
    let payload_path = loaded.dir.join(&entry.source);
    let payload_meta = std::fs::symlink_metadata(&payload_path)
        .map_err(|e| ApplyError::Internal(format!("payload unreadable: {e:?}")))?;
    if !payload_meta.file_type().is_file() {
        return Err(ApplyError::Internal("payload is not a regular file".into()));
    }
    let payload = std::fs::read(&payload_path)
        .map_err(|e| ApplyError::Internal(format!("read payload: {e:?}")))?;
    if payload.len() > 256 * 1024 {
        return Err(ApplyError::Internal("payload exceeds cap".into()));
    }
    let desired_hash = crate::hash::file_content_hash(&payload);

    // PRECHECK: lstat + symlink refusal + ownership + expected-before.
    let current = observe::observe_file(&abs);
    if current.is_symlink {
        journal(PH_FAILED, None, Some("symlink at target")).map_err(ApplyError::Internal)?;
        return Err(ApplyError::Conflict(format!(
            "file {}: symlink at target; refusing",
            op.target
        )));
    }
    if current.is_non_regular && current.exists {
        journal(PH_FAILED, None, Some("non-regular target")).map_err(ApplyError::Internal)?;
        return Err(ApplyError::Conflict(format!(
            "file {}: non-regular file at target",
            op.target
        )));
    }
    match op.kind {
        OperationKind::FileCreate => {
            if current.exists {
                journal(PH_FAILED, None, Some("target appeared since plan"))
                    .map_err(ApplyError::Internal)?;
                return Err(ApplyError::Conflict(format!(
                    "file {}: target appeared since planning; re-plan",
                    op.target
                )));
            }
        }
        _ => {
            if !current.exists {
                // Target vanished since plan: FileUpdate becomes a create only
                // when the disappearance is consistent... fail closed instead:
                // re-plan. (Adopted conflicts with vanished targets also fail.)
                journal(PH_FAILED, None, Some("target vanished since plan"))
                    .map_err(ApplyError::Internal)?;
                return Err(ApplyError::Conflict(format!(
                    "file {}: target vanished since planning; re-plan",
                    op.target
                )));
            }
            if let Some(expected) = &op.expected_before {
                if current.content_hash.as_ref() != Some(expected) {
                    journal(PH_FAILED, None, Some("precondition mismatch"))
                        .map_err(ApplyError::Internal)?;
                    return Err(ApplyError::Conflict(format!(
                        "file {}: changed since planning (TOCTOU guard); re-plan",
                        op.target
                    )));
                }
            } else if !adopt.contains(&op.target) {
                // No fingerprint recorded and not an adoption: only safe when
                // content already matches (noop below handles it).
            }
            // Ownership: managed or adopted, else refuse.
            let owned = is_owned(state_dir, &plan.profile_identity, &op.target);
            if !owned && !adopt.contains(&op.target) {
                journal(PH_FAILED, None, Some("unmanaged")).map_err(ApplyError::Internal)?;
                return Err(ApplyError::Conflict(format!(
                    "file {} exists and is not managed; use --adopt",
                    op.target
                )));
            }
            // Already at desired state → noop (idempotency).
            if current.content_hash.as_ref() == Some(&desired_hash) {
                journal(PH_PRECHECK, None, Some("already at desired state; noop"))
                    .map_err(ApplyError::Internal)?;
                journal(PH_DONE, None, Some("noop")).map_err(ApplyError::Internal)?;
                let _ = crate::state::record_owned(
                    state_dir,
                    "file",
                    &op.target,
                    &plan.profile_identity,
                    Some(&desired_hash),
                    crate::state::now_secs(),
                );
                return Ok(Some(OpOutcome {
                    op_id: op.id.clone(),
                    target: op.target.clone(),
                    kind: format!("{:?}", op.kind),
                    result: "noop".into(),
                    backup_sha: None,
                }));
            }
        }
    }
    journal(PH_PRECHECK, None, Some("preconditions hold")).map_err(ApplyError::Internal)?;
    failpoint(PH_PRECHECK)?;

    // BACKUP existing content (create: nothing to back up).
    let mut backup_sha: Option<String> = None;
    if current.exists {
        let bytes = std::fs::read(&abs)
            .map_err(|e| ApplyError::Internal(format!("read target for backup: {e:?}")))?;
        let sha = crate::backup::put(state_dir, &bytes).map_err(ApplyError::Internal)?;
        backup_sha = Some(sha.clone());
        journal(PH_BACKUP, Some(&sha), Some("backup stored")).map_err(ApplyError::Internal)?;
    } else {
        journal(PH_BACKUP, None, Some("no previous content")).map_err(ApplyError::Internal)?;
    }
    failpoint(PH_BACKUP)?;

    // EXECUTE: atomic write (temp in target dir + fsync + rename + dir fsync).
    if let Some(parent) = abs.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            let _ = journal(
                PH_FAILED,
                backup_sha.as_deref(),
                Some("create parent failed"),
            );
            return Err(ApplyError::OpFailed {
                op_id: op.id.clone(),
                target: op.target.clone(),
                message: format!("create parent dir: {e:?}"),
            });
        }
    }
    // Re-check symlink status immediately before write (TOCTOU narrowing).
    if has_symlink_parent(&abs) {
        journal(
            PH_FAILED,
            None,
            Some("symlink parent swapped in before write"),
        )
        .map_err(ApplyError::Internal)?;
        return Err(ApplyError::Conflict(format!(
            "file {}: a parent directory became a symlink before write; refusing",
            op.target
        )));
    }
    if let Ok(m) = std::fs::symlink_metadata(&abs) {
        if m.file_type().is_symlink() {
            journal(PH_FAILED, None, Some("symlink swapped in before write"))
                .map_err(ApplyError::Internal)?;
            return Err(ApplyError::Conflict(format!(
                "file {}: symlink appeared before write; refusing",
                op.target
            )));
        }
    }
    let tmp = abs.with_extension("tmp-configctl");
    std::fs::write(&tmp, &payload).map_err(|e| ApplyError::OpFailed {
        op_id: op.id.clone(),
        target: op.target.clone(),
        message: format!("write temp file: {e:?}"),
    })?;
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    // Mode: explicit profile mode on create; preserve-or-profile on update.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bits = match (&op.kind, &entry.mode) {
            (_, Some(m)) => crate::paths::parse_mode(m).ok(),
            (OperationKind::FileCreate, None) => Some(0o644),
            _ => None,
        };
        if let Some(b) = bits {
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(b & 0o7777));
        } else if op.kind == OperationKind::FileUpdate {
            if let Ok(m) = std::fs::symlink_metadata(&abs) {
                let _ = std::fs::set_permissions(&tmp, m.permissions());
            }
        }
    }
    std::fs::rename(&tmp, &abs).map_err(|e| ApplyError::OpFailed {
        op_id: op.id.clone(),
        target: op.target.clone(),
        message: format!("atomic rename: {e:?}"),
    })?;
    if let Some(parent) = abs.parent() {
        if let Ok(f) = std::fs::File::open(parent) {
            let _ = f.sync_all();
        }
    }
    journal(PH_EXECUTE, backup_sha.as_deref(), Some("written")).map_err(ApplyError::Internal)?;
    failpoint(PH_EXECUTE)?;

    // POSTCHECK: content must equal desired.
    let after = observe::observe_file(&abs);
    if after.content_hash.as_ref() != Some(&desired_hash) {
        journal(PH_FAILED, backup_sha.as_deref(), Some("postcheck mismatch"))
            .map_err(ApplyError::Internal)?;
        return Err(ApplyError::OpFailed {
            op_id: op.id.clone(),
            target: op.target.clone(),
            message: "postcheck: written content does not match desired".into(),
        });
    }
    journal(PH_POSTCHECK, backup_sha.as_deref(), Some("verified")).map_err(ApplyError::Internal)?;
    failpoint(PH_POSTCHECK)?;
    journal(PH_DONE, backup_sha.as_deref(), Some("ok")).map_err(ApplyError::Internal)?;
    failpoint(PH_DONE)?;

    // Ownership + history.
    let _ = crate::state::record_owned(
        state_dir,
        "file",
        &op.target,
        &plan.profile_identity,
        Some(&desired_hash),
        crate::state::now_secs(),
    );
    if adopt.contains(&op.target) {
        let _ = crate::state::record_history(
            state_dir,
            Some(plan_id),
            Some(&op.id),
            "adopt",
            "ok",
            Some(&op.target),
            crate::state::now_secs(),
        );
    }
    Ok(Some(OpOutcome {
        op_id: op.id.clone(),
        target: op.target.clone(),
        kind: format!("{:?}", op.kind),
        result: "ok".into(),
        backup_sha,
    }))
}

fn is_owned(state_dir: &Path, profile: &str, target: &str) -> bool {
    crate::state::ownership_for_profile(state_dir, profile)
        .map(|s| s.contains(&("file".to_string(), target.to_string())))
        .unwrap_or(false)
}

/// Env apply: set managed literals in the owned env file (atomic rewrite).
#[allow(clippy::too_many_arguments)]
fn execute_env_op(
    state_dir: &Path,
    plan_id: &str,
    plan: &Plan,
    loaded: &LoadedProfile,
    home: &Path,
    op: &Operation,
    journal: JournalFn,
    failpoint: FailFn,
) -> Result<Option<OpOutcome>, ApplyError> {
    journal(PH_INTENT, None, Some(&op.summary)).map_err(ApplyError::Internal)?;
    failpoint(PH_INTENT)?;
    let desired = match loaded
        .profile
        .environment
        .as_ref()
        .and_then(|e| e.get(&op.target))
    {
        Some(EnvLiteral::Value(v)) => v.clone(),
        _ => {
            journal(PH_FAILED, None, Some("no literal in profile"))
                .map_err(ApplyError::Internal)?;
            return Err(ApplyError::Internal(format!(
                "env {}: no literal value in profile",
                op.target
            )));
        }
    };
    let env_path = home.join(MANAGED_ENV_REL);
    let current = read_env_map(&env_path).get(&op.target).cloned();
    if current.as_deref() == Some(desired.as_str()) {
        journal(PH_PRECHECK, None, Some("already set; noop")).map_err(ApplyError::Internal)?;
        journal(PH_DONE, None, Some("noop")).map_err(ApplyError::Internal)?;
        return Ok(Some(OpOutcome {
            op_id: op.id.clone(),
            target: op.target.clone(),
            kind: format!("{:?}", op.kind),
            result: "noop".into(),
            backup_sha: None,
        }));
    }
    journal(PH_PRECHECK, None, Some("differs")).map_err(ApplyError::Internal)?;
    failpoint(PH_PRECHECK)?;
    // Backup previous env file content when present.
    let mut backup_sha: Option<String> = None;
    if env_path.exists() {
        if let Ok(bytes) = std::fs::read(&env_path) {
            let sha = crate::backup::put(state_dir, &bytes).map_err(ApplyError::Internal)?;
            backup_sha = Some(sha.clone());
            journal(PH_BACKUP, Some(&sha), Some("backup stored")).map_err(ApplyError::Internal)?;
        }
    } else {
        journal(PH_BACKUP, None, Some("no previous env file")).map_err(ApplyError::Internal)?;
    }
    failpoint(PH_BACKUP)?;
    // Rewrite atomically: managed names updated, everything else preserved.
    let mut managed: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    if let Some(env) = &loaded.profile.environment {
        for (k, v) in env {
            if let EnvLiteral::Value(lit) = v {
                managed.insert(k.clone(), lit.clone());
            }
        }
    }
    let mut current_map = read_env_map(&env_path);
    for (k, v) in &managed {
        current_map.insert(k.clone(), v.clone());
    }
    let mut text = String::from("# Managed by configctl (do not hand-edit managed entries)\n");
    for (k, v) in &current_map {
        text.push_str(&format!("{k}={v}\n"));
    }
    if let Some(parent) = env_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ApplyError::OpFailed {
            op_id: op.id.clone(),
            target: op.target.clone(),
            message: format!("create env dir: {e:?}"),
        })?;
    }
    let tmp = env_path.with_extension("tmp-configctl");
    std::fs::write(&tmp, text.as_bytes()).map_err(|e| ApplyError::OpFailed {
        op_id: op.id.clone(),
        target: op.target.clone(),
        message: format!("write env temp: {e:?}"),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &env_path).map_err(|e| ApplyError::OpFailed {
        op_id: op.id.clone(),
        target: op.target.clone(),
        message: format!("commit env file: {e:?}"),
    })?;
    journal(PH_EXECUTE, backup_sha.as_deref(), Some("written")).map_err(ApplyError::Internal)?;
    failpoint(PH_EXECUTE)?;
    // POSTCHECK.
    if read_env_map(&env_path).get(&op.target) != Some(&desired) {
        journal(PH_FAILED, backup_sha.as_deref(), Some("postcheck mismatch"))
            .map_err(ApplyError::Internal)?;
        return Err(ApplyError::OpFailed {
            op_id: op.id.clone(),
            target: op.target.clone(),
            message: "postcheck: env value not set".into(),
        });
    }
    journal(PH_POSTCHECK, backup_sha.as_deref(), Some("verified")).map_err(ApplyError::Internal)?;
    journal(PH_DONE, backup_sha.as_deref(), Some("ok")).map_err(ApplyError::Internal)?;
    failpoint(PH_DONE)?;
    let _ = crate::state::record_owned(
        state_dir,
        "env",
        &op.target,
        &plan.profile_identity,
        Some(&crate::hash::env_value_hash(&desired)),
        crate::state::now_secs(),
    );
    let _ = crate::state::record_history(
        state_dir,
        Some(plan_id),
        Some(&op.id),
        "apply",
        "ok",
        Some(&op.target),
        crate::state::now_secs(),
    );
    Ok(Some(OpOutcome {
        op_id: op.id.clone(),
        target: op.target.clone(),
        kind: format!("{:?}", op.kind),
        result: "ok".into(),
        backup_sha,
    }))
}

/// Upper bound for shell startup files we will append an include block to.
/// Larger files are refused rather than truncated (a truncating edit would
/// destroy the user's shell configuration).
const MAX_RC_BYTES: u64 = 1024 * 1024;

/// Shared TOCTOU gate for the v1.2 env artifacts: the bytes read now must be
/// exactly what the plan recorded as `expected_before`.
///
/// Error strings name the target only — never values.
fn guard_expected_before(
    op: &Operation,
    current: Option<&[u8]>,
    re_run_hint: &str,
) -> Result<(), ApplyError> {
    match (&op.expected_before, current) {
        (Some(want), Some(cur)) if crate::hash::file_content_hash(cur) == *want => Ok(()),
        (None, None) => Ok(()),
        (None, Some(_)) => Err(ApplyError::Conflict(format!(
            "{} exists but the plan expected it to be absent; {re_run_hint}",
            op.target
        ))),
        (Some(_), None) => Err(ApplyError::Conflict(format!(
            "{} is missing but the plan expected it to exist; {re_run_hint}",
            op.target
        ))),
        _ => Err(ApplyError::Conflict(format!(
            "{} changed since planning; {re_run_hint}",
            op.target
        ))),
    }
}

/// Atomic full-content write with an optional pre-write backup.
///
/// Returns the backup sha (when a previous file existed).
fn atomic_write_with_backup(
    state_dir: &Path,
    op: &Operation,
    abs: &Path,
    bytes: &[u8],
    mode_on_create: u32,
    journal: JournalFn,
    failpoint: FailFn,
) -> Result<(Option<String>, OpOutcome), ApplyError> {
    // Backup the previous content when present.
    let mut backup_sha: Option<String> = None;
    match std::fs::read(abs) {
        Ok(previous) => {
            let sha = crate::backup::put(state_dir, &previous).map_err(ApplyError::Internal)?;
            backup_sha = Some(sha.clone());
            journal(PH_BACKUP, Some(&sha), Some("backup stored")).map_err(ApplyError::Internal)?;
        }
        Err(_) => {
            journal(PH_BACKUP, None, Some("no previous file")).map_err(ApplyError::Internal)?;
        }
    }
    failpoint(PH_BACKUP)?;

    // Re-check symlink status immediately before write (TOCTOU narrowing).
    if has_symlink_parent(abs) {
        journal(
            PH_FAILED,
            None,
            Some("symlink parent swapped in before write"),
        )
        .map_err(ApplyError::Internal)?;
        return Err(ApplyError::Conflict(format!(
            "{}: a parent directory became a symlink before write; refusing",
            op.target
        )));
    }
    if let Ok(m) = std::fs::symlink_metadata(abs) {
        if m.file_type().is_symlink() {
            journal(PH_FAILED, None, Some("symlink swapped in before write"))
                .map_err(ApplyError::Internal)?;
            return Err(ApplyError::Conflict(format!(
                "{}: symlink appeared before write; refusing",
                op.target
            )));
        }
    }

    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ApplyError::OpFailed {
            op_id: op.id.clone(),
            target: op.target.clone(),
            message: format!("create {}: {e:?}", parent.display()),
        })?;
    }

    let tmp = abs.with_extension("tmp-configctl");
    std::fs::write(&tmp, bytes).map_err(|e| ApplyError::OpFailed {
        op_id: op.id.clone(),
        target: op.target.clone(),
        message: format!("write temp file: {e:?}"),
    })?;
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = match std::fs::symlink_metadata(abs) {
            Ok(m) if m.file_type().is_file() => m.permissions().mode() & 0o7777,
            _ => mode_on_create,
        };
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    }
    std::fs::rename(&tmp, abs).map_err(|e| ApplyError::OpFailed {
        op_id: op.id.clone(),
        target: op.target.clone(),
        message: format!("atomic rename: {e:?}"),
    })?;
    if let Some(parent) = abs.parent() {
        if let Ok(f) = std::fs::File::open(parent) {
            let _ = f.sync_all();
        }
    }
    // Postcheck: the file must now hold exactly the desired bytes.
    let written = std::fs::read(abs).map_err(|e| ApplyError::OpFailed {
        op_id: op.id.clone(),
        target: op.target.clone(),
        message: format!("postcheck read: {e:?}"),
    })?;
    if crate::hash::file_content_hash(&written) != op.desired_after.clone().unwrap_or_default() {
        journal(PH_FAILED, None, Some("postcheck mismatch")).map_err(ApplyError::Internal)?;
        return Err(ApplyError::OpFailed {
            op_id: op.id.clone(),
            target: op.target.clone(),
            message: "postcheck: written content does not match the plan".into(),
        });
    }
    journal(PH_POSTCHECK, backup_sha.as_deref(), Some("verified")).map_err(ApplyError::Internal)?;
    journal(PH_DONE, backup_sha.as_deref(), Some("ok")).map_err(ApplyError::Internal)?;
    failpoint(PH_DONE)?;
    Ok((
        backup_sha.clone(),
        OpOutcome {
            op_id: op.id.clone(),
            target: op.target.clone(),
            kind: format!("{:?}", op.kind),
            result: "ok".into(),
            backup_sha,
        },
    ))
}

/// v1.2: write the canonical managed shell env file.
///
/// Composed from the profile's `[environment]` literals — the same source of
/// truth as `environment.d/90-configctl.conf` — so both artifacts always
/// agree. Secret entries stay references and are never written here; the
/// composed content is additionally screened for secret-like values and a
/// trip is a hard error (defense in depth).
#[allow(clippy::too_many_arguments)]
fn execute_env_file_write(
    state_dir: &Path,
    plan_id: &str,
    plan: &Plan,
    loaded: &LoadedProfile,
    home: &Path,
    op: &Operation,
    journal: JournalFn,
    failpoint: FailFn,
) -> Result<Option<OpOutcome>, ApplyError> {
    journal(PH_INTENT, None, Some(&op.summary)).map_err(ApplyError::Internal)?;
    failpoint(PH_INTENT)?;

    let entries = crate::plan::canonical_env_entries(loaded);
    if let Some(name) = crate::envmap::first_secret_like(&entries) {
        journal(PH_FAILED, None, Some("secret-like value refused"))
            .map_err(ApplyError::Internal)?;
        return Err(ApplyError::Internal(format!(
            "env file: refusing to write secret-like value {name} to the canonical shell env file"
        )));
    }
    let desired = crate::envmap::canonical_env_file(&entries);
    let abs = home.join(crate::envmap::CANONICAL_REL);

    let current = std::fs::read(&abs).ok();
    if current.as_deref() == Some(desired.as_bytes()) {
        journal(PH_PRECHECK, None, Some("already current; noop")).map_err(ApplyError::Internal)?;
        journal(PH_DONE, None, Some("noop")).map_err(ApplyError::Internal)?;
        return Ok(Some(OpOutcome {
            op_id: op.id.clone(),
            target: op.target.clone(),
            kind: format!("{:?}", op.kind),
            result: "noop".into(),
            backup_sha: None,
        }));
    }
    guard_expected_before(op, current.as_deref(), "re-run `configctl env consolidate`")?;
    journal(PH_PRECHECK, None, Some("differs")).map_err(ApplyError::Internal)?;
    failpoint(PH_PRECHECK)?;

    let (backup_sha, mut outcome) = atomic_write_with_backup(
        state_dir,
        op,
        &abs,
        desired.as_bytes(),
        0o600,
        journal,
        failpoint,
    )?;
    let _ = crate::state::record_owned(
        state_dir,
        "envfile",
        &op.target,
        &plan.profile_identity,
        Some(&crate::hash::file_content_hash(desired.as_bytes())),
        crate::state::now_secs(),
    );
    let _ = crate::state::record_history(
        state_dir,
        Some(plan_id),
        Some(&op.id),
        "apply",
        "ok",
        Some(&op.target),
        crate::state::now_secs(),
    );
    outcome.backup_sha = backup_sha;
    Ok(Some(outcome))
}

/// v1.2: append the marker-delimited include block to a shell startup file.
///
/// Additive and marker-delimited, so it is class `SAFE_REPRODUCE` even though
/// it changes shell startup: it is backed up, fully reversible, and never
/// rewrites anything outside the two markers.
#[allow(clippy::too_many_arguments)]
fn execute_include_line_op(
    state_dir: &Path,
    plan_id: &str,
    plan: &Plan,
    home: &Path,
    op: &Operation,
    journal: JournalFn,
    failpoint: FailFn,
) -> Result<Option<OpOutcome>, ApplyError> {
    journal(PH_INTENT, None, Some(&op.summary)).map_err(ApplyError::Internal)?;
    failpoint(PH_INTENT)?;

    crate::paths::validate_file_target(&op.target).map_err(ApplyError::Usage)?;
    let abs = observe::expand_target(&op.target, home)
        .ok_or_else(|| ApplyError::Usage(format!("invalid target {:?}", op.target)))?;
    if has_symlink_parent(&abs) {
        return Err(ApplyError::Conflict(format!(
            "{}: a parent directory is a symlink; refusing",
            op.target
        )));
    }
    if let Ok(m) = std::fs::symlink_metadata(&abs) {
        if m.file_type().is_symlink() {
            return Err(ApplyError::Conflict(format!(
                "{} is a symlink; refusing",
                op.target
            )));
        }
        if !m.file_type().is_file() {
            return Err(ApplyError::Conflict(format!(
                "{} is not a regular file; refusing",
                op.target
            )));
        }
        if m.len() > MAX_RC_BYTES {
            return Err(ApplyError::Conflict(format!(
                "{} is larger than {MAX_RC_BYTES} bytes; refusing to rewrite it",
                op.target
            )));
        }
    }

    let current = std::fs::read(&abs).ok();
    guard_expected_before(op, current.as_deref(), "re-run `configctl env consolidate`")?;

    let current_str = current
        .as_ref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    let updated = crate::envmap::ensure_include_block(&current_str);
    if updated == current_str {
        journal(PH_PRECHECK, None, Some("already present; noop")).map_err(ApplyError::Internal)?;
        journal(PH_DONE, None, Some("noop")).map_err(ApplyError::Internal)?;
        return Ok(Some(OpOutcome {
            op_id: op.id.clone(),
            target: op.target.clone(),
            kind: format!("{:?}", op.kind),
            result: "noop".into(),
            backup_sha: None,
        }));
    }
    journal(PH_PRECHECK, None, Some("include block missing")).map_err(ApplyError::Internal)?;
    failpoint(PH_PRECHECK)?;

    let (backup_sha, mut outcome) = atomic_write_with_backup(
        state_dir,
        op,
        &abs,
        updated.as_bytes(),
        0o644,
        journal,
        failpoint,
    )?;
    let _ = crate::state::record_owned(
        state_dir,
        "rcfile",
        &op.target,
        &plan.profile_identity,
        Some(&crate::hash::file_content_hash(updated.as_bytes())),
        crate::state::now_secs(),
    );
    let _ = crate::state::record_history(
        state_dir,
        Some(plan_id),
        Some(&op.id),
        "apply",
        "ok",
        Some(&op.target),
        crate::state::now_secs(),
    );
    outcome.backup_sha = backup_sha;
    Ok(Some(outcome))
}

/// Parse managed-env file bytes into a `KEY → VALUE` map.
///
/// Shared by apply (postchecks) and rollback (like-for-like guards) so both
/// stages interpret the same bytes identically: first occurrence wins,
/// comments/blanks skipped, invalid names ignored. Returns `None` when the
/// bytes are not valid UTF-8 (fail-closed: callers must refuse, never guess).
pub fn parse_env_bytes(bytes: &[u8]) -> Option<std::collections::BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(eq) = line.find('=') else { continue };
        let name = line[..eq].trim();
        if crate::paths::validate_env_name(name).is_ok() {
            map.entry(name.to_string())
                .or_insert_with(|| line[eq + 1..].trim().to_string());
        }
    }
    Some(map)
}

pub(crate) fn read_env_map(path: &Path) -> std::collections::BTreeMap<String, String> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return std::collections::BTreeMap::new();
    };
    if !meta.file_type().is_file() || meta.len() > 64 * 1024 {
        return std::collections::BTreeMap::new();
    }
    let Ok(bytes) = std::fs::read(path) else {
        return std::collections::BTreeMap::new();
    };
    parse_env_bytes(&bytes).unwrap_or_default()
}

/// Service apply: `systemctl --user enable/disable` (or start/stop for running
/// scope). Verifies final state.
fn execute_service_op(
    state_dir: &Path,
    plan_id: &str,
    plan: &Plan,
    runner: &dyn CommandRunner,
    op: &Operation,
    journal: JournalFn,
    failpoint: FailFn,
) -> Result<Option<OpOutcome>, ApplyError> {
    journal(PH_INTENT, None, Some(&op.summary)).map_err(ApplyError::Internal)?;
    failpoint(PH_INTENT)?;
    if !crate::paths::validate_service_unit(&op.target) {
        return Err(ApplyError::Usage(format!("invalid unit {:?}", op.target)));
    }
    let scope = op
        .details
        .get("scope")
        .map(|s| s.as_str())
        .unwrap_or("enabled");
    let want_on = op.kind == OperationKind::ServiceEnable;
    // PRECHECK via is-enabled / is-active.
    let probe_cmd = if scope == "running" {
        "is-active"
    } else {
        "is-enabled"
    };
    let probe_ok_value = if scope == "running" {
        "active"
    } else {
        "enabled"
    };
    let current_on = {
        let req = CommandRequest::new("systemctl", ["--user", probe_cmd, op.target.as_str()])
            .output_cap(8 * 1024);
        match runner.run(&req) {
            Ok(o) => Some(o.stdout.trim() == probe_ok_value),
            Err(_) => {
                return Err(ApplyError::ProviderUnavailable(
                    "systemd user manager unavailable".into(),
                ));
            }
        }
    };
    if current_on == Some(want_on) {
        journal(PH_PRECHECK, None, Some("already at desired state; noop"))
            .map_err(ApplyError::Internal)?;
        journal(PH_DONE, None, Some("noop")).map_err(ApplyError::Internal)?;
        return Ok(Some(OpOutcome {
            op_id: op.id.clone(),
            target: op.target.clone(),
            kind: format!("{:?}", op.kind),
            result: "noop".into(),
            backup_sha: None,
        }));
    }
    journal(PH_PRECHECK, None, Some("differs")).map_err(ApplyError::Internal)?;
    failpoint(PH_PRECHECK)?;
    journal(
        PH_BACKUP,
        None,
        Some("service state revertible; no content backup"),
    )
    .map_err(ApplyError::Internal)?;
    let verb = match (scope, want_on) {
        ("running", true) => "start",
        ("running", false) => "stop",
        (_, true) => "enable",
        _ => "disable",
    };
    let req = CommandRequest::new("systemctl", ["--user", verb, op.target.as_str()])
        .output_cap(32 * 1024);
    let out = runner
        .run(&req)
        .map_err(|_| ApplyError::ProviderUnavailable("systemd user manager unavailable".into()))?;
    journal(
        PH_EXECUTE,
        None,
        out.status.map(|s| s.to_string()).as_deref(),
    )
    .map_err(ApplyError::Internal)?;
    failpoint(PH_EXECUTE)?;
    if out.status != Some(0) {
        journal(PH_FAILED, None, Some("systemctl failed")).map_err(ApplyError::Internal)?;
        return Err(ApplyError::OpFailed {
            op_id: op.id.clone(),
            target: op.target.clone(),
            message: format!("systemctl --user {verb} {} failed", op.target),
        });
    }
    // POSTCHECK.
    let after = {
        let req = CommandRequest::new("systemctl", ["--user", probe_cmd, op.target.as_str()])
            .output_cap(8 * 1024);
        runner
            .run(&req)
            .ok()
            .map(|o| o.stdout.trim() == probe_ok_value)
    };
    if after != Some(want_on) {
        journal(PH_FAILED, None, Some("postcheck mismatch")).map_err(ApplyError::Internal)?;
        return Err(ApplyError::OpFailed {
            op_id: op.id.clone(),
            target: op.target.clone(),
            message: format!("postcheck: {} did not reach desired state", op.target),
        });
    }
    journal(PH_POSTCHECK, None, Some("verified")).map_err(ApplyError::Internal)?;
    journal(PH_DONE, None, Some("ok")).map_err(ApplyError::Internal)?;
    failpoint(PH_DONE)?;
    let _ = crate::state::record_history(
        state_dir,
        Some(plan_id),
        Some(&op.id),
        "apply",
        "ok",
        Some(&op.target),
        crate::state::now_secs(),
    );
    let _ = plan;
    Ok(Some(OpOutcome {
        op_id: op.id.clone(),
        target: op.target.clone(),
        kind: format!("{:?}", op.kind),
        result: "ok".into(),
        backup_sha: None,
    }))
}

/// Git apply: `git config --global <key> <value>` (fixed argv; values are the
/// user's own non-secret config, never secrets).
#[allow(clippy::too_many_arguments)]
fn execute_git_op(
    state_dir: &Path,
    plan_id: &str,
    plan: &Plan,
    loaded: &LoadedProfile,
    runner: &dyn CommandRunner,
    op: &Operation,
    journal: JournalFn,
    failpoint: FailFn,
) -> Result<Option<OpOutcome>, ApplyError> {
    journal(PH_INTENT, None, Some(&op.summary)).map_err(ApplyError::Internal)?;
    failpoint(PH_INTENT)?;
    let (key, desired) = match op.target.as_str() {
        "user.name" => (
            "user.name",
            loaded
                .profile
                .git
                .as_ref()
                .and_then(|g| g.user_name.clone()),
        ),
        "user.email" => (
            "user.email",
            loaded
                .profile
                .git
                .as_ref()
                .and_then(|g| g.user_email.clone()),
        ),
        other => {
            return Err(ApplyError::Internal(format!(
                "unsupported git target {other:?}"
            )));
        }
    };
    let Some(desired) = desired else {
        return Err(ApplyError::Internal(
            "git value missing from profile".into(),
        ));
    };
    // PRECHECK: read current.
    let current = {
        let req = CommandRequest::new("git", ["config", "--global", key]).output_cap(4 * 1024);
        runner
            .run(&req)
            .ok()
            .filter(|o| o.status == Some(0))
            .map(|o| o.stdout.trim().to_string())
    };
    if current.as_deref() == Some(desired.as_str()) {
        journal(PH_PRECHECK, None, Some("already set; noop")).map_err(ApplyError::Internal)?;
        journal(PH_DONE, None, Some("noop")).map_err(ApplyError::Internal)?;
        return Ok(Some(OpOutcome {
            op_id: op.id.clone(),
            target: op.target.clone(),
            kind: format!("{:?}", op.kind),
            result: "noop".into(),
            backup_sha: None,
        }));
    }
    journal(PH_PRECHECK, None, Some("differs")).map_err(ApplyError::Internal)?;
    failpoint(PH_PRECHECK)?;
    journal(PH_BACKUP, None, Some("git config revertible via re-apply"))
        .map_err(ApplyError::Internal)?;
    let req = CommandRequest::new("git", ["config", "--global", key, desired.as_str()])
        .output_cap(8 * 1024);
    let out = runner
        .run(&req)
        .map_err(|_| ApplyError::ProviderUnavailable("git unavailable".into()))?;
    journal(
        PH_EXECUTE,
        None,
        out.status.map(|s| s.to_string()).as_deref(),
    )
    .map_err(ApplyError::Internal)?;
    failpoint(PH_EXECUTE)?;
    if out.status != Some(0) {
        journal(PH_FAILED, None, Some("git config failed")).map_err(ApplyError::Internal)?;
        return Err(ApplyError::OpFailed {
            op_id: op.id.clone(),
            target: op.target.clone(),
            message: format!("git config --global {key} failed"),
        });
    }
    journal(PH_POSTCHECK, None, Some("ok")).map_err(ApplyError::Internal)?;
    journal(PH_DONE, None, Some("ok")).map_err(ApplyError::Internal)?;
    failpoint(PH_DONE)?;
    let _ = crate::state::record_history(
        state_dir,
        Some(plan_id),
        Some(&op.id),
        "apply",
        "ok",
        Some(&op.target),
        crate::state::now_secs(),
    );
    let _ = plan;
    Ok(Some(OpOutcome {
        op_id: op.id.clone(),
        target: op.target.clone(),
        kind: format!("{:?}", op.kind),
        result: "ok".into(),
        backup_sha: None,
    }))
}

/// True when any existing ancestor of `abs` is a symlink (fail-closed: an
/// unreadable ancestor stops the walk and is treated as unsafe).
fn has_symlink_parent(abs: &Path) -> bool {
    let mut cur = abs.parent();
    while let Some(p) = cur {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => return true,
            Ok(_) => {}
            // A non-existent ancestor cannot be a symlink; apply creates it.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Anything else (permission denied, I/O error) is unknowable:
            // fail closed rather than guessing.
            Err(_) => return true,
        }
        cur = p.parent();
    }
    false
}

fn is_package_installed(runner: &dyn CommandRunner, provider: &str, name: &str) -> bool {
    match provider {
        "dnf" => match runner.run(&crate::package_managers::DnfProvider::is_installed_request(
            name,
        )) {
            Ok(o) => crate::package_managers::DnfProvider::parse_installed(&o),
            Err(_) => false,
        },
        "pacman" => {
            match runner.run(&crate::package_managers::PacmanProvider::is_installed_request(name)) {
                Ok(o) => crate::package_managers::PacmanProvider::parse_installed(&o),
                Err(_) => false,
            }
        }
        "apk" => {
            match runner.run(&crate::package_managers::ApkProvider::is_installed_request(
                name,
            )) {
                Ok(o) => crate::package_managers::ApkProvider::parse_installed(&o),
                Err(_) => false,
            }
        }
        // apt (and any legacy op without a recognized manager): the v1
        // `dpkg-query` status probe. Unknown managers never reach here —
        // the install dispatch above refuses them first.
        _ => {
            let req = CommandRequest::new("dpkg-query", ["-W", "-f=${Status}", name])
                .output_cap(8 * 1024);
            match runner.run(&req) {
                Ok(o) => o.status == Some(0) && o.stdout.contains("install ok installed"),
                Err(_) => false,
            }
        }
    }
}
