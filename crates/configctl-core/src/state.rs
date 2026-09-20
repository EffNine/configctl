//! SQLite-backed state store (P0 §9).
//!
//! Layout:
//!
//! ```text
//! $STATE/                 (0700)
//! ├── state.db            (0600, SQLite)
//! ├── plans/<id>.json    (0600, redacted plan documents)
//! ├── backups/objects/   (0600, content-addressed — P7)
//! └── audit.log           (0600, append-only)
//! ```
//!
//! The store never contains secret values: plans carry hashes/refs only
//! (enforced by the plan model having no value fields).

use crate::plan::Plan;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Default state directory: `~/.local/state/configctl`.
pub fn default_state_dir() -> PathBuf {
    if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(state).join("configctl")
    } else if let Some(home) = dirs_state_home_fallback() {
        home.join(".local/state/configctl")
    } else {
        PathBuf::from(".configctl-state")
    }
}

fn dirs_state_home_fallback() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Resolve the effective state dir: explicit override wins.
pub fn resolve_state_dir(override_dir: Option<&str>) -> PathBuf {
    match override_dir {
        Some(d) => shellexpand_home(d),
        None => default_state_dir(),
    }
}

fn shellexpand_home(raw: &str) -> PathBuf {
    if raw == "~" {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(raw));
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

/// Ensure the state directory exists with safe permissions (0700) and open
/// the database (creating schema on first use).
pub fn ensure_state_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create state dir: {e:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        for sub in ["plans", "backups", "backups/objects"] {
            let p = dir.join(sub);
            std::fs::create_dir_all(&p).map_err(|e| format!("create {}: {e:?}", p.display()))?;
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
        }
    }
    #[cfg(not(unix))]
    {
        for sub in ["plans", "backups", "backups/objects"] {
            let p = dir.join(sub);
            std::fs::create_dir_all(&p).map_err(|e| format!("create {}: {e:?}", p.display()))?;
        }
    }
    // Touch + open DB to force schema creation.
    let _conn = open_db(dir)?;
    Ok(())
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join("state.db")
}

fn open_db(dir: &Path) -> Result<Connection, String> {
    let path = db_path(dir);
    let conn = Connection::open(&path).map_err(|e| format!("open state db: {e:?}"))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS resources (
           id INTEGER PRIMARY KEY,
           kind TEXT NOT NULL,
           locator TEXT NOT NULL,
           owner_profile TEXT,
           fingerprint TEXT,
           updated_at INTEGER NOT NULL,
           UNIQUE(kind, locator)
         );
         CREATE TABLE IF NOT EXISTS plans (
           id TEXT PRIMARY KEY,
           profile TEXT NOT NULL,
           profile_hash TEXT NOT NULL,
           state_hash TEXT NOT NULL,
           plan_hash TEXT NOT NULL,
           status TEXT NOT NULL,
           approved_at INTEGER,
           created_at INTEGER NOT NULL,
           doc_path TEXT NOT NULL,
           bundle_dir TEXT NOT NULL DEFAULT ''
         );
         CREATE TABLE IF NOT EXISTS journal (
           id INTEGER PRIMARY KEY,
           plan_id TEXT NOT NULL,
           op_id TEXT NOT NULL,
           phase TEXT NOT NULL,
           backup_sha TEXT,
           detail TEXT,
           recorded_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS history (
           id INTEGER PRIMARY KEY,
           plan_id TEXT,
           op_id TEXT,
           action TEXT NOT NULL,
           result TEXT NOT NULL,
           recorded_at INTEGER NOT NULL,
           detail TEXT
         );
         CREATE INDEX IF NOT EXISTS journal_by_plan ON journal(plan_id);",
    )
    .map_err(|e| format!("init state db: {e:?}"))?;
    // Best-effort migration for databases created before `bundle_dir` existed.
    let _ = conn.execute(
        "ALTER TABLE plans ADD COLUMN bundle_dir TEXT NOT NULL DEFAULT ''",
        [],
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(conn)
}

/// Plan execution status.
pub const STATUS_PLANNED: &str = "planned";
pub const STATUS_APPROVED: &str = "approved";
pub const STATUS_APPLYING: &str = "applying";
pub const STATUS_APPLIED: &str = "applied";
pub const STATUS_PARTIAL: &str = "partial";
pub const STATUS_ROLLED_BACK: &str = "rolled_back";

/// Save a plan (immutable after creation): DB row + `<dir>/plans/<id>.json`.
/// Refuses to overwrite an existing plan id with different content.
/// `bundle_dir` is the canonical profile bundle path the plan was built from
/// (needed at apply time to read payloads; verified against `profile_hash`).
pub fn save_plan(dir: &Path, plan: &Plan, bundle_dir: &Path) -> Result<PathBuf, String> {
    ensure_state_dir(dir)?;
    let doc_path = dir.join("plans").join(format!("{}.json", plan.plan_id));
    if doc_path.exists() {
        let existing =
            std::fs::read_to_string(&doc_path).map_err(|e| format!("read existing plan: {e:?}"))?;
        let v: serde_json::Value =
            serde_json::from_str(&existing).map_err(|e| format!("parse existing plan: {e}"))?;
        if v.get("plan_hash").and_then(|h| h.as_str()) != Some(plan.plan_hash.as_str()) {
            return Err(format!(
                "plan {} already exists with different content (immutable)",
                plan.plan_id
            ));
        }
        return Ok(doc_path);
    }
    let json = serde_json::to_string_pretty(plan).map_err(|e| format!("serialize plan: {e}"))?;
    // Secret-safety: the plan model has no value fields, but scan the
    // serialized form for `secret://`-adjacent accidents is unnecessary;
    // instead assert no suspicious literal slipped in via summary text.
    debug_assert!(!json.contains("BEGIN PRIVATE KEY"));
    std::fs::write(&doc_path, &json).map_err(|e| format!("write plan: {e:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&doc_path, std::fs::Permissions::from_mode(0o600));
    }
    let conn = open_db(dir)?;
    conn.execute(
        "INSERT OR IGNORE INTO plans (id, profile, profile_hash, state_hash, plan_hash, status, created_at, doc_path, bundle_dir)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            plan.plan_id,
            plan.profile_identity,
            plan.profile_hash,
            plan.observed_state_fingerprint,
            plan.plan_hash,
            STATUS_PLANNED,
            plan.created_at,
            doc_path.to_string_lossy().to_string(),
            bundle_dir.to_string_lossy().to_string(),
        ],
    )
    .map_err(|e| format!("save plan row: {e:?}"))?;
    append_audit(
        dir,
        &format!(
            "plan {} profile={} hash={}",
            plan.plan_id, plan.profile_identity, plan.plan_hash
        ),
    )?;
    Ok(doc_path)
}

/// Load a plan by id (verifies the stored hash matches the document).
/// Returns `(plan, status, bundle_dir)`.
/// Why a persisted plan could not be loaded.
///
/// Callers map these categories to exit semantics: `Unavailable` is an
/// infrastructure failure (exit 1), `Invalid` is a usage error (exit 2), and
/// `NotFound`/`Tampered` are conflict-class (exit 5, re-plan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanLoadError {
    /// The plan id itself is malformed.
    Invalid(String),
    /// The state store could not be opened or read (missing dir, IO,
    /// permissions) — not a conflict.
    Unavailable(String),
    /// No plan with that id exists.
    NotFound(String),
    /// The plan document failed its integrity or hash check.
    Tampered(String),
}

impl std::fmt::Display for PlanLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanLoadError::Invalid(m)
            | PlanLoadError::Unavailable(m)
            | PlanLoadError::NotFound(m)
            | PlanLoadError::Tampered(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for PlanLoadError {}

/// Most recent persisted plan id (any profile), if any.
///
/// Backs `apply --last` / `rollback --last`. A missing state directory means
/// no plans exist yet (not an error).
pub fn newest_plan_id(dir: &Path) -> Result<Option<String>, PlanLoadError> {
    if !dir.is_dir() {
        return Ok(None);
    }
    let conn = open_db(dir).map_err(PlanLoadError::Unavailable)?;
    conn.query_row(
        "SELECT id FROM plans ORDER BY created_at DESC, rowid DESC LIMIT 1",
        [],
        |r| r.get(0),
    )
    .optional()
    .map_err(|e| PlanLoadError::Unavailable(format!("query latest plan: {e:?}")))
}

pub fn load_plan(dir: &Path, plan_id: &str) -> Result<(Plan, String, PathBuf), PlanLoadError> {
    if plan_id.contains('/') || plan_id.contains('\0') || plan_id.contains("..") {
        return Err(PlanLoadError::Invalid(format!(
            "invalid plan id: {plan_id:?}"
        )));
    }
    let conn = match open_db(dir) {
        Ok(conn) => conn,
        // No state directory yet: no plan with this id can exist, so this is
        // "unknown plan" (conflict-class), not an infrastructure failure.
        Err(_) if !dir.is_dir() => {
            return Err(PlanLoadError::NotFound(format!(
                "unknown plan id: {plan_id:?} (no state store yet)"
            )));
        }
        Err(e) => return Err(PlanLoadError::Unavailable(e)),
    };
    let (plan_hash, status, bundle_dir): (String, String, String) = conn
        .query_row(
            "SELECT plan_hash, status, bundle_dir FROM plans WHERE id = ?1",
            params![plan_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|_| PlanLoadError::NotFound(format!("unknown plan id: {plan_id:?}")))?;
    let doc_path = dir.join("plans").join(format!("{plan_id}.json"));
    let text = std::fs::read_to_string(&doc_path)
        .map_err(|e| PlanLoadError::Unavailable(format!("read plan doc: {e:?}")))?;
    let plan: Plan = serde_json::from_str(&text)
        .map_err(|e| PlanLoadError::Tampered(format!("parse plan doc: {e}")))?;
    if plan.plan_hash != plan_hash || plan.plan_id != plan_id {
        return Err(PlanLoadError::Tampered(format!(
            "plan {plan_id} failed integrity check (tampered?)"
        )));
    }
    // Recompute the semantic hash to detect on-disk edits.
    let recomputed = crate::plan::compute_plan_hash(&plan);
    if recomputed != plan.plan_hash {
        return Err(PlanLoadError::Tampered(format!(
            "plan {plan_id} hash mismatch: document was modified after creation"
        )));
    }
    Ok((plan, status, PathBuf::from(bundle_dir)))
}

/// Mark a plan approved (bound to the exact hash).
pub fn approve_plan(dir: &Path, plan_id: &str, now: i64) -> Result<(), String> {
    let conn = open_db(dir)?;
    let changed = conn
        .execute(
            "UPDATE plans SET status = ?1, approved_at = ?2 WHERE id = ?3 AND status IN ('planned','approved')",
            params![STATUS_APPROVED, now, plan_id],
        )
        .map_err(|e| format!("approve plan: {e:?}"))?;
    if changed == 0 {
        return Err(format!(
            "plan {plan_id} cannot be approved from its current state"
        ));
    }
    append_audit(dir, &format!("approve {plan_id}"))?;
    Ok(())
}

/// Set plan execution status.
pub fn set_plan_status(dir: &Path, plan_id: &str, status: &str) -> Result<(), String> {
    let conn = open_db(dir)?;
    conn.execute(
        "UPDATE plans SET status = ?1 WHERE id = ?2",
        params![status, plan_id],
    )
    .map_err(|e| format!("set plan status: {e:?}"))?;
    append_audit(dir, &format!("plan {plan_id} -> {status}"))?;
    Ok(())
}

/// Latest plan id for a profile (by rowid order).
pub fn latest_plan_id(dir: &Path, profile: &str) -> Result<Option<String>, String> {
    let conn = open_db(dir)?;
    let mut stmt = conn
        .prepare("SELECT id FROM plans WHERE profile = ?1 ORDER BY rowid DESC LIMIT 1")
        .map_err(|e| format!("query plans: {e:?}"))?;
    let mut rows = stmt
        .query(params![profile])
        .map_err(|e| format!("query plans: {e:?}"))?;
    if let Some(r) = rows.next().map_err(|e| format!("query plans: {e:?}"))? {
        let id: String = r.get(0).map_err(|e| format!("query plans: {e:?}"))?;
        Ok(Some(id))
    } else {
        Ok(None)
    }
}

/// Record a journal entry.
pub fn journal(
    dir: &Path,
    plan_id: &str,
    op_id: &str,
    phase: &str,
    backup_sha: Option<&str>,
    detail: Option<&str>,
    now: i64,
) -> Result<(), String> {
    let conn = open_db(dir)?;
    conn.execute(
        "INSERT INTO journal (plan_id, op_id, phase, backup_sha, detail, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![plan_id, op_id, phase, backup_sha, detail, now],
    )
    .map_err(|e| format!("journal: {e:?}"))?;
    Ok(())
}

/// Journal phases for one plan, in record order.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub op_id: String,
    pub phase: String,
    pub backup_sha: Option<String>,
    pub detail: Option<String>,
    pub recorded_at: i64,
}

pub fn journal_for_plan(dir: &Path, plan_id: &str) -> Result<Vec<JournalEntry>, String> {
    let conn = open_db(dir)?;
    let mut stmt = conn
        .prepare("SELECT op_id, phase, backup_sha, detail, recorded_at FROM journal WHERE plan_id = ?1 ORDER BY id")
        .map_err(|e| format!("query journal: {e:?}"))?;
    let rows = stmt
        .query_map(params![plan_id], |r| {
            Ok(JournalEntry {
                op_id: r.get(0)?,
                phase: r.get(1)?,
                backup_sha: r.get(2)?,
                detail: r.get(3)?,
                recorded_at: r.get(4)?,
            })
        })
        .map_err(|e| format!("query journal: {e:?}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| format!("query journal: {e:?}"))?);
    }
    Ok(out)
}

/// Record history.
pub fn record_history(
    dir: &Path,
    plan_id: Option<&str>,
    op_id: Option<&str>,
    action: &str,
    result: &str,
    detail: Option<&str>,
    now: i64,
) -> Result<(), String> {
    let conn = open_db(dir)?;
    conn.execute(
        "INSERT INTO history (plan_id, op_id, action, result, recorded_at, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![plan_id, op_id, action, result, now, detail],
    )
    .map_err(|e| format!("history: {e:?}"))?;
    Ok(())
}

/// List plans newest-first: `(id, profile, status, created_at)`.
pub fn list_plans(dir: &Path) -> Result<Vec<(String, String, String, i64)>, String> {
    let conn = open_db(dir)?;
    let mut stmt = conn
        .prepare("SELECT id, profile, status, created_at FROM plans ORDER BY rowid DESC")
        .map_err(|e| format!("query plans: {e:?}"))?;
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(|e| format!("query plans: {e:?}"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| format!("query plans: {e:?}"))?);
    }
    Ok(out)
}

/// Ownership: mark a file target owned by a profile with its fingerprint.
pub fn record_owned(
    dir: &Path,
    kind: &str,
    locator: &str,
    owner_profile: &str,
    fingerprint: Option<&str>,
    now: i64,
) -> Result<(), String> {
    let conn = open_db(dir)?;
    conn.execute(
        "INSERT INTO resources (kind, locator, owner_profile, fingerprint, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(kind, locator) DO UPDATE SET owner_profile=excluded.owner_profile, fingerprint=excluded.fingerprint, updated_at=excluded.updated_at",
        params![kind, locator, owner_profile, fingerprint, now],
    )
    .map_err(|e| format!("record ownership: {e:?}"))?;
    Ok(())
}

/// One ownership record from the `resources` table.
#[derive(Debug, Clone)]
pub struct ResourceRow {
    pub kind: String,
    pub locator: String,
    pub owner_profile: Option<String>,
    pub fingerprint: Option<String>,
    pub updated_at: i64,
}

/// Ownership lookup for a single `(kind, locator)`. Missing store -> `None`.
pub fn find_resource(dir: &Path, kind: &str, locator: &str) -> Result<Option<ResourceRow>, String> {
    if !dir.is_dir() {
        return Ok(None);
    }
    let conn = open_db(dir)?;
    conn.query_row(
        "SELECT kind, locator, owner_profile, fingerprint, updated_at \
         FROM resources WHERE kind = ?1 AND locator = ?2",
        params![kind, locator],
        |r| {
            Ok(ResourceRow {
                kind: r.get(0)?,
                locator: r.get(1)?,
                owner_profile: r.get(2)?,
                fingerprint: r.get(3)?,
                updated_at: r.get(4)?,
            })
        },
    )
    .optional()
    .map_err(|e| format!("query resource: {e:?}"))
}

/// Ownership snapshot for one profile.
pub fn ownership_for_profile(
    dir: &Path,
    profile: &str,
) -> Result<BTreeSet<(String, String)>, String> {
    let conn = open_db(dir)?;
    let mut stmt = conn
        .prepare("SELECT kind, locator FROM resources WHERE owner_profile = ?1")
        .map_err(|e| format!("query ownership: {e:?}"))?;
    let rows = stmt
        .query_map(params![profile], |r| {
            let k: String = r.get(0)?;
            let l: String = r.get(1)?;
            Ok((k, l))
        })
        .map_err(|e| format!("query ownership: {e:?}"))?;
    let mut out = BTreeSet::new();
    for r in rows {
        out.insert(r.map_err(|e| format!("query ownership: {e:?}"))?);
    }
    Ok(out)
}

/// Append a redacted line to the audit log.
pub fn append_audit(dir: &Path, line: &str) -> Result<(), String> {
    use std::io::Write;
    let path = dir.join("audit.log");
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open audit log: {e:?}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    writeln!(f, "{now} {line}").map_err(|e| format!("write audit log: {e:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Generate a new plan id: `01`-style timestamp + random suffix (no external
/// ULID dep; deterministic tests pass explicit ids).
pub fn new_plan_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let rand_part = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        std::thread::current().id().hash(&mut h);
        now.hash(&mut h);
        format!("{:06}", h.finish() % 1_000_000)
    };
    format!("{now:013}-{rand_part}")
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exit-code semantics depend on this classification.
    #[test]
    fn load_plan_classifies_errors() {
        let tmp = tempfile::tempdir().unwrap();

        // No state store yet -> no plan can exist (conflict-class).
        let missing = tmp.path().join("no-state");
        match load_plan(&missing, "p-1") {
            Err(PlanLoadError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }

        // A real but empty state store -> no such plan.
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        match load_plan(&state, "p-1") {
            Err(PlanLoadError::NotFound(_)) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }

        // Malformed id -> usage error.
        match load_plan(&state, "../escape") {
            Err(PlanLoadError::Invalid(_)) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }

        // Store present but broken (db path is a directory) -> infrastructure.
        let broken = tmp.path().join("broken");
        std::fs::create_dir_all(broken.join("state.db")).unwrap();
        match load_plan(&broken, "p-1") {
            Err(PlanLoadError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn newest_plan_id_is_the_newest_and_missing_store_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("state");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(newest_plan_id(&dir).unwrap(), None);

        {
            let conn = open_db(&dir).unwrap();
            for (id, created) in [("p-old", 100i64), ("p-new", 200i64)] {
                conn.execute(
                    "INSERT INTO plans (id, profile, profile_hash, state_hash, plan_hash, \
                     status, approved_at, created_at, doc_path, bundle_dir) \
                     VALUES (?1, 'p', 'ph', 'sh', 'planh', 'planned', NULL, ?2, '', '')",
                    params![id, created],
                )
                .unwrap();
            }
        }
        assert_eq!(newest_plan_id(&dir).unwrap().as_deref(), Some("p-new"));

        let missing = tmp.path().join("nope");
        assert_eq!(newest_plan_id(&missing).unwrap(), None);
    }
}
