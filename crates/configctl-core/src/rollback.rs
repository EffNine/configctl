//! Rollback + crash recovery (P7).
//!
//! - File rollback is strong: every mutating file/env op took a
//!   content-addressed backup; rollback restores it atomically (or removes a
//!   file that apply created, when the current content still matches).
//! - Package rollback is conservative and report-only: configctl never
//!   uninstalls or downgrades packages automatically.
//! - Service/git rollback is report-only in v1 (prior states are not recorded
//!   as restorable snapshots).
//! - Crash recovery: interrupted journals are classified per operation as
//!   `safe_to_resume` / `requires_rollback` / `requires_manual` / `unknown`.
//!   Recovery is always explicit (`rollback`, re-`plan`); never silent.
//!
//! Rollback honesty per operation is surfaced as
//! `ROLLBACK_SUPPORTED / ROLLBACK_PARTIAL / ROLLBACK_UNSUPPORTED`.

use crate::apply::MANAGED_ENV_REL;
use crate::observe;
use crate::plan::{Operation, OperationKind, Plan};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Rollback support disclosure per operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackSupport {
    Supported,
    Partial,
    Unsupported,
}

pub fn support_of(op: &Operation) -> RollbackSupport {
    match op.kind {
        OperationKind::FileCreate | OperationKind::FileUpdate => RollbackSupport::Supported,
        OperationKind::EnvironmentSchemaChange => RollbackSupport::Supported,
        OperationKind::PackageInstall
        | OperationKind::PackageVersionMismatch
        | OperationKind::Unsupported
        | OperationKind::NoOp => RollbackSupport::Unsupported,
        OperationKind::ServiceEnable
        | OperationKind::ServiceDisable
        | OperationKind::GitConfigChange
        | OperationKind::FileConflict => RollbackSupport::Partial,
    }
}

/// Recovery classification for one journaled operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryClass {
    /// Nothing was written (last phase INTENT/PRECHECK, or no journal yet).
    SafeToResume,
    /// A backup exists and the target may have been written: restore it.
    RequiresRollback,
    /// No backup or ambiguous content: human decision required.
    RequiresManual,
    /// Cannot determine (unknown phases, missing plan...).
    Unknown,
}

/// Per-operation recovery diagnosis.
#[derive(Debug, Clone)]
pub struct OpRecovery {
    pub op_id: String,
    pub target: String,
    pub kind: String,
    pub last_phase: Option<String>,
    pub class: RecoveryClass,
    pub reason: String,
}

/// Classify every operation of a plan from its journal.
pub fn classify_plan(state_dir: &Path, plan_id: &str) -> Result<Vec<OpRecovery>, String> {
    let (plan, _status, _) =
        crate::state::load_plan(state_dir, plan_id).map_err(|e| e.to_string())?;
    let journal = crate::state::journal_for_plan(state_dir, plan_id)?;
    // Last phase per op (journal is in record order).
    let mut last: BTreeMap<String, (String, Option<String>)> = BTreeMap::new();
    for e in &journal {
        last.insert(e.op_id.clone(), (e.phase.clone(), e.backup_sha.clone()));
    }
    let mut out = Vec::new();
    for op in executable_or_conflict(&plan) {
        let entry = last.get(&op.id);
        let (class, reason) = match entry.map(|(p, _)| p.as_str()) {
            None => (
                RecoveryClass::SafeToResume,
                "operation never started".to_string(),
            ),
            Some("DONE") => (
                RecoveryClass::RequiresRollback,
                "operation completed; restore its backup to undo".to_string(),
            ),
            Some("FAILED") => (
                RecoveryClass::RequiresManual,
                "operation failed; inspect before recovering".to_string(),
            ),
            Some("INTENT") | Some("PRECHECK") => (
                RecoveryClass::SafeToResume,
                "interrupted before any write".to_string(),
            ),
            Some("BACKUP") => (
                RecoveryClass::SafeToResume,
                "interrupted after backup, before write; target verified before any resume"
                    .to_string(),
            ),
            Some("EXECUTE") | Some("POSTCHECK") => {
                let has_backup = entry.and_then(|(_, b)| b.clone()).is_some();
                if has_backup || matches!(op.kind, OperationKind::FileCreate) {
                    (
                        RecoveryClass::RequiresRollback,
                        "interrupted after write; restore backup (or remove created file)"
                            .to_string(),
                    )
                } else {
                    (
                        RecoveryClass::RequiresManual,
                        "interrupted after write with no backup".to_string(),
                    )
                }
            }
            Some("ROLLBACK") | Some("RECOVERED") => {
                (RecoveryClass::SafeToResume, "already recovered".to_string())
            }
            _ => (
                RecoveryClass::Unknown,
                "unrecognized journal phase".to_string(),
            ),
        };
        out.push(OpRecovery {
            op_id: op.id.clone(),
            target: op.target.clone(),
            kind: format!("{:?}", op.kind),
            last_phase: entry.map(|(p, _)| p.clone()),
            class,
            reason,
        });
    }
    Ok(out)
}

fn executable_or_conflict(plan: &Plan) -> Vec<&Operation> {
    plan.operations
        .iter()
        .filter(|o| {
            !matches!(
                o.kind,
                OperationKind::NoOp
                    | OperationKind::Unsupported
                    | OperationKind::PackageVersionMismatch
            )
        })
        .collect()
}

/// True when the journal shows no write-phase for any op (safe for apply to
/// accept an explicit re-run after an `applying` interruption).
pub fn journal_shows_no_mutation(state_dir: &Path, plan_id: &str) -> bool {
    let Ok(journal) = crate::state::journal_for_plan(state_dir, plan_id) else {
        return false;
    };
    !journal.iter().any(|e| {
        matches!(
            e.phase.as_str(),
            "BACKUP" | "EXECUTE" | "POSTCHECK" | "DONE" | "FAILED"
        )
    })
}

/// Options for rollback.
#[derive(Debug, Clone, Default)]
pub struct RollbackOptions {
    pub yes: bool,
    pub dry_run: bool,
}

/// Rollback report.
#[derive(Debug, Clone, Default)]
pub struct RollbackReport {
    pub plan_id: String,
    pub restored: Vec<String>,
    pub removed: Vec<String>,
    pub manual: Vec<String>,
    pub dry_run: bool,
}

/// Rollback errors (CLI maps to exit codes 2/4/5/1).
#[derive(Debug, Clone)]
pub enum RollbackError {
    Usage(String),
    Declined(String),
    Conflict(String),
    Internal(String),
}

/// Roll back an applied or partial plan.
///
/// Reverse execution order; file/env ops restore from CAS backups; packages,
/// services, and git entries are reported for manual handling (never
/// auto-removed/downgraded). Requires the mutation lock. Explicit only.
pub fn rollback_plan(
    state_dir: &Path,
    plan_id: &str,
    home: &Path,
    opts: &RollbackOptions,
    approve: &dyn Fn(&RollbackReport) -> bool,
) -> Result<RollbackReport, RollbackError> {
    let (plan, status, _) = crate::state::load_plan(state_dir, plan_id).map_err(|e| match e {
        crate::state::PlanLoadError::Unavailable(_) => RollbackError::Internal(e.to_string()),
        crate::state::PlanLoadError::Invalid(_) => RollbackError::Usage(e.to_string()),
        _ => RollbackError::Conflict(e.to_string()),
    })?;
    match status.as_str() {
        "applied" | "partial" | "applying" => {}
        "planned" | "approved" => {
            return Err(RollbackError::Usage(format!(
                "plan {plan_id} never applied (status {status}); nothing to roll back"
            )));
        }
        "rolled_back" => {
            return Err(RollbackError::Usage(format!(
                "plan {plan_id} was already rolled back"
            )));
        }
        other => return Err(RollbackError::Internal(format!("unknown status {other:?}"))),
    }
    // Refuse while an op needs manual recovery (never guess).
    let diagnosis = classify_plan(state_dir, plan_id).map_err(RollbackError::Internal)?;
    if diagnosis
        .iter()
        .any(|d| d.class == RecoveryClass::RequiresManual)
    {
        return Err(RollbackError::Conflict(
            "plan needs manual recovery first; see `configctl doctor`".into(),
        ));
    }

    let journal =
        crate::state::journal_for_plan(state_dir, plan_id).map_err(RollbackError::Internal)?;
    // Latest DONE backup per op; plus latest backup for interrupted ops that
    // wrote but never reached DONE (BACKUP/EXECUTE/POSTCHECK entries carry
    // the sha — this is what crash recovery restores).
    let mut done_backup: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut interrupt_backup: BTreeMap<String, String> = BTreeMap::new();
    for e in &journal {
        if e.phase == "DONE" {
            done_backup.insert(e.op_id.clone(), e.backup_sha.clone());
            interrupt_backup.remove(&e.op_id);
        } else if let Some(sha) = e.backup_sha.clone() {
            if !done_backup.contains_key(&e.op_id) {
                interrupt_backup.insert(e.op_id.clone(), sha);
            }
        }
    }
    let backup_for = |op_id: &str| -> Option<Option<String>> {
        if let Some(b) = done_backup.get(op_id) {
            return Some(b.clone());
        }
        interrupt_backup.get(op_id).map(|s| Some(s.clone()))
    };

    // Build the work list in reverse execution order.
    let mut ops: Vec<&Operation> = plan.operations.iter().collect();
    ops.reverse();
    let mut report = RollbackReport {
        plan_id: plan_id.into(),
        dry_run: opts.dry_run,
        ..Default::default()
    };
    for op in ops {
        match support_of(op) {
            RollbackSupport::Unsupported => {
                if matches!(
                    op.kind,
                    OperationKind::PackageInstall
                        | OperationKind::PackageVersionMismatch
                        | OperationKind::Unsupported
                ) && !matches!(op.kind, OperationKind::NoOp)
                {
                    // Only report real package mutations, not markers.
                    if op.kind == OperationKind::PackageInstall {
                        report.manual.push(format!(
                            "package {}: installed by apply; v1 never auto-removes (manual: apt remove {})",
                            op.target, op.target
                        ));
                    }
                }
            }
            RollbackSupport::Partial => {
                report.manual.push(format!(
                    "{} {}: previous state not snapshotted; verify manually",
                    op.kind_name(),
                    op.target
                ));
            }
            RollbackSupport::Supported => {
                // Only ops that actually executed (DONE) or were interrupted
                // after backup (BACKUP/EXECUTE/POSTCHECK with a sha).
                // Preview only here (dry): the real restore runs under the
                // lock after approval below.
                let Some(backup) = backup_for(&op.id) else {
                    continue;
                };
                match rollback_file_op(state_dir, home, &plan, op, backup, true) {
                    Ok(action) => match action {
                        RollbackAction::Restored => report.restored.push(op.target.clone()),
                        RollbackAction::Removed => report.removed.push(op.target.clone()),
                        RollbackAction::Noop => {}
                    },
                    Err(reason) => {
                        return Err(RollbackError::Conflict(format!(
                            "cannot roll back {}: {reason}; manual recovery required",
                            op.target
                        )));
                    }
                }
            }
        }
    }

    if report.restored.is_empty()
        && report.removed.is_empty()
        && !report.manual.is_empty()
        && !opts.dry_run
    {
        // Nothing restorable, only manual items: still record the attempt?
        // No — refuse to mark rolled_back when nothing was restored, so the
        // user can still recover files later. Report the manual list.
    }

    if !opts.dry_run {
        if !opts.yes && !approve(&report) {
            return Err(RollbackError::Declined(
                "rollback declined; no changes made".into(),
            ));
        }
        let _lock = crate::lock::acquire(state_dir).map_err(RollbackError::Conflict)?;
        // Re-execute the restores under the lock (double-checked: the preview
        // above ran unlocked; now perform for real).
        let mut real = RollbackReport {
            plan_id: plan_id.into(),
            dry_run: false,
            ..Default::default()
        };
        for op in plan.operations.iter().rev() {
            if support_of(op) != RollbackSupport::Supported {
                continue;
            }
            let Some(backup) = backup_for(&op.id) else {
                continue;
            };
            match rollback_file_op(state_dir, home, &plan, op, backup, false) {
                Ok(RollbackAction::Restored) => real.restored.push(op.target.clone()),
                Ok(RollbackAction::Removed) => real.removed.push(op.target.clone()),
                Ok(RollbackAction::Noop) => {}
                Err(reason) => {
                    return Err(RollbackError::Conflict(format!(
                        "cannot roll back {}: {reason}",
                        op.target
                    )));
                }
            }
            crate::state::journal(
                state_dir,
                plan_id,
                &op.id,
                "ROLLBACK",
                None,
                Some("rolled back"),
                crate::state::now_secs(),
            )
            .map_err(RollbackError::Internal)?;
        }
        real.manual = report.manual.clone();
        crate::state::set_plan_status(state_dir, plan_id, crate::state::STATUS_ROLLED_BACK)
            .map_err(RollbackError::Internal)?;
        let _ = crate::state::record_history(
            state_dir,
            Some(plan_id),
            None,
            "rollback",
            "rolled_back",
            None,
            crate::state::now_secs(),
        );
        return Ok(real);
    }
    Ok(report)
}

enum RollbackAction {
    Restored,
    Removed,
    Noop,
}

/// Restore one file/env op from its backup (or remove a created file).
/// Pure check-then-act with symlink guards; `dry_run` only checks.
///
/// Safety rule: a restore/removal happens only when the target still holds
/// exactly what apply wrote. File ops compare file-content identity against
/// `desired_after` (both are whole-file hashes); env ops compare the managed
/// literal values (value-domain hashes) plus whole-file key/value equality
/// against the pre-apply backup. Any divergence refuses fail-closed so
/// rollback can never clobber external edits.
fn rollback_file_op(
    state_dir: &Path,
    home: &Path,
    plan: &Plan,
    op: &Operation,
    backup: Option<String>,
    dry_run: bool,
) -> Result<RollbackAction, String> {
    let abs: PathBuf = match op.kind {
        OperationKind::EnvironmentSchemaChange => home.join(MANAGED_ENV_REL),
        _ => observe::expand_target(&op.target, home)
            .ok_or_else(|| format!("invalid target {:?}", op.target))?,
    };
    crate::paths::validate_file_target(&op.target)
        .map_err(|e| e.to_string())
        .or_else(|_| {
            // Env ops use VAR targets; validate the managed path instead.
            if op.kind == OperationKind::EnvironmentSchemaChange {
                Ok(())
            } else {
                Err(format!("invalid target {:?}", op.target))
            }
        })?;
    let current = observe::observe_file(&abs);
    if current.is_symlink {
        return Err("symlink at target; refusing".into());
    }
    match backup {
        Some(sha) => {
            let bytes =
                crate::backup::get(state_dir, &sha).map_err(|e| format!("backup missing: {e}"))?;
            // Fail closed when the target no longer holds what apply wrote.
            guard_unchanged_since_apply(plan, op, &abs, &current, Some(&bytes))?;
            if dry_run {
                return Ok(RollbackAction::Restored);
            }
            atomic_restore(&abs, &bytes)?;
            // Update ownership fingerprint to the restored content.
            let fp = crate::hash::file_content_hash(&bytes);
            let kind = if op.kind == OperationKind::EnvironmentSchemaChange {
                "env"
            } else {
                "file"
            };
            let _ = crate::state::record_owned(
                state_dir,
                kind,
                &op.target,
                &plan.profile_identity,
                Some(&fp),
                crate::state::now_secs(),
            );
            Ok(RollbackAction::Restored)
        }
        None => {
            // File was created by apply: remove only when current content
            // still matches what apply wrote (else manual).
            if !current.exists {
                return Ok(RollbackAction::Noop);
            }
            guard_unchanged_since_apply(plan, op, &abs, &current, None)?;
            if dry_run {
                return Ok(RollbackAction::Removed);
            }
            std::fs::remove_file(&abs).map_err(|e| format!("remove created file: {e:?}"))?;
            Ok(RollbackAction::Removed)
        }
    }
}

/// Refuse unless the target still holds exactly what apply wrote.
///
/// - File ops: `desired_after` is a file-content hash and
///   `observe_file().content_hash` uses the same canonical representation
///   (`hash::file_content_hash`), so the comparison is like-for-like.
/// - Env ops: `desired_after` is a *value* hash, which must never be compared
///   against a file-content hash. Compare value-vs-value for every managed
///   literal in the plan, and additionally require whole-file equality with
///   the pre-apply state (`backup_bytes`, or the empty map when apply created
///   the file) so added/removed/altered unmanaged entries also refuse.
///
/// Error strings name targets only — never values or hashes.
fn guard_unchanged_since_apply(
    plan: &Plan,
    op: &Operation,
    abs: &Path,
    current: &observe::FileObs,
    backup_bytes: Option<&[u8]>,
) -> Result<(), String> {
    const REFUSE: &str = "changed since apply; manual recovery required";
    if op.kind == OperationKind::EnvironmentSchemaChange {
        return guard_env_unchanged(plan, op, abs, backup_bytes);
    }
    match (&current.content_hash, &op.desired_after) {
        (Some(cur), Some(want)) if cur == want => Ok(()),
        _ => Err(REFUSE.into()),
    }
}

/// Env-op divergence guard (see `guard_unchanged_since_apply`).
fn guard_env_unchanged(
    plan: &Plan,
    op: &Operation,
    abs: &Path,
    backup_bytes: Option<&[u8]>,
) -> Result<(), String> {
    const REFUSE: &str = "managed env file changed since apply; manual recovery required";
    // Managed desires from this plan: VAR -> desired value hash (value domain).
    let mut managed: BTreeMap<String, String> = BTreeMap::new();
    for o in &plan.operations {
        if o.kind == OperationKind::EnvironmentSchemaChange {
            if let Some(h) = &o.desired_after {
                managed.insert(o.target.clone(), h.clone());
            }
        }
    }
    // The op under rollback must carry its own desired state; without it
    // there is nothing trustworthy to compare against.
    let want_self = op
        .desired_after
        .as_ref()
        .ok_or_else(|| REFUSE.to_string())?;
    if !managed.contains_key(&op.target) {
        return Err(REFUSE.into());
    }
    let current_bytes = std::fs::read(abs).map_err(|_| REFUSE.to_string())?;
    let current_map =
        crate::apply::parse_env_bytes(&current_bytes).ok_or_else(|| REFUSE.to_string())?;
    // (a) Every managed literal must still hold exactly its desired value.
    // Value hash vs value hash — like-for-like within the value domain.
    for (var, want) in &managed {
        match current_map.get(var) {
            Some(cur) if crate::hash::env_value_hash(cur) == *want => {}
            _ => return Err(REFUSE.into()),
        }
    }
    // The op's own target is covered by the loop above; double-check it
    // directly so a plan that somehow omits it still fails closed.
    match current_map.get(&op.target) {
        Some(cur) if crate::hash::env_value_hash(cur) == *want_self => {}
        _ => return Err(REFUSE.into()),
    }
    // (b) Whole-file equality: current must equal pre-apply plus managed
    // desires, so externally added/removed/altered entries also refuse.
    let mut expected_keys: BTreeMap<String, Option<String>> = BTreeMap::new();
    match backup_bytes {
        Some(bytes) => {
            let before = crate::apply::parse_env_bytes(bytes).ok_or_else(|| REFUSE.to_string())?;
            for (k, v) in &before {
                expected_keys.insert(k.clone(), Some(v.clone()));
            }
        }
        None => {
            // Apply created the file: no pre-existing entries may remain.
        }
    }
    for var in managed.keys() {
        expected_keys.insert(var.clone(), None);
    }
    if current_map.len() != expected_keys.len() {
        return Err(REFUSE.into());
    }
    for (key, before_value) in &expected_keys {
        match (current_map.get(key), before_value) {
            (Some(_), None) => {} // Managed key: value already checked in (a).
            (Some(cur), Some(before)) if cur == before => {}
            _ => return Err(REFUSE.into()),
        }
    }
    Ok(())
}

/// Atomically replace `abs` with `bytes` (temp + rename, symlink-guarded).
fn atomic_restore(abs: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create parent: {e:?}"))?;
    }
    if let Ok(m) = std::fs::symlink_metadata(abs) {
        if m.file_type().is_symlink() {
            return Err("symlink at target; refusing".into());
        }
    }
    let tmp = abs.with_extension("tmp-rollback");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write temp: {e:?}"))?;
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, abs).map_err(|e| format!("commit restore: {e:?}"))?;
    Ok(())
}

/// Restore a single file target from its most recent backup (targeted
/// rollback: `configctl rollback ~/.gitconfig`).
pub fn rollback_target(
    state_dir: &Path,
    target: &str,
    home: &Path,
    dry_run: bool,
) -> Result<RollbackReport, RollbackError> {
    crate::paths::validate_file_target(target).map_err(RollbackError::Usage)?;
    let abs = observe::expand_target(target, home)
        .ok_or_else(|| RollbackError::Usage(format!("invalid target {target:?}")))?;
    // Search plans newest-first for a DONE file op on this target with backup.
    let plans = crate::state::list_plans(state_dir).map_err(RollbackError::Internal)?;
    for (plan_id, _, _, _) in plans {
        let Ok((plan, _, _)) = crate::state::load_plan(state_dir, &plan_id) else {
            continue;
        };
        for op in plan.operations.iter().rev() {
            if op.target != target {
                continue;
            }
            if !matches!(
                op.kind,
                OperationKind::FileCreate | OperationKind::FileUpdate
            ) {
                continue;
            }
            let Ok(journal) = crate::state::journal_for_plan(state_dir, &plan_id) else {
                continue;
            };
            let backup = journal
                .iter()
                .rev()
                .find(|e| e.op_id == op.id && e.phase == "DONE")
                .and_then(|e| e.backup_sha.clone());
            let Some(sha) = backup else { continue };
            let bytes = crate::backup::get(state_dir, &sha).map_err(RollbackError::Internal)?;
            // Fail closed when the target no longer holds what apply wrote.
            // Both sides are canonical file-content identities
            // (`hash::file_content_hash` hex digests), so string equality is
            // the like-for-like comparison. Targeted rollback only handles
            // file ops, whose `desired_after` is always file-domain.
            let current = observe::observe_file(&abs);
            if current.is_symlink {
                return Err(RollbackError::Conflict(
                    "symlink at target; refusing".into(),
                ));
            }
            match (&current.content_hash, &op.desired_after) {
                (Some(cur), Some(want)) if cur == want => {}
                _ => {
                    return Err(RollbackError::Conflict(format!(
                        "cannot roll back {target:?}: changed since apply; manual recovery required"
                    )));
                }
            }
            if dry_run {
                return Ok(RollbackReport {
                    plan_id,
                    restored: vec![target.into()],
                    ..Default::default()
                });
            }
            let _lock = crate::lock::acquire(state_dir).map_err(RollbackError::Conflict)?;
            atomic_restore(&abs, &bytes).map_err(RollbackError::Conflict)?;
            let fp = crate::hash::file_content_hash(&bytes);
            let _ = crate::state::record_owned(
                state_dir,
                "file",
                target,
                &plan.profile_identity,
                Some(&fp),
                crate::state::now_secs(),
            );
            let _ = crate::state::record_history(
                state_dir,
                Some(&plan_id),
                Some(&op.id),
                "rollback",
                "ok",
                Some(target),
                crate::state::now_secs(),
            );
            return Ok(RollbackReport {
                plan_id,
                restored: vec![target.into()],
                ..Default::default()
            });
        }
    }
    Err(RollbackError::Usage(format!(
        "no backup found for {target:?}"
    )))
}

trait KindName {
    fn kind_name(&self) -> &'static str;
}

impl KindName for Operation {
    fn kind_name(&self) -> &'static str {
        match self.kind {
            OperationKind::PackageInstall => "package",
            OperationKind::PackageVersionMismatch => "package",
            OperationKind::FileCreate | OperationKind::FileUpdate | OperationKind::FileConflict => {
                "file"
            }
            OperationKind::EnvironmentSchemaChange => "env",
            OperationKind::ServiceEnable | OperationKind::ServiceDisable => "service",
            OperationKind::GitConfigChange => "git",
            OperationKind::NoOp => "noop",
            OperationKind::Unsupported => "unsupported",
        }
    }
}
