//! Global mutation lock (P4).
//!
//! Only one mutating configctl process (`apply`, `rollback`) may run at once.
//! The lock is an `flock` on `<state>/.lock` (non-blocking: a held lock fails
//! fast with a clear error instead of hanging). Read-only commands (`plan`,
//! `verify`) never take it.

use std::fs::OpenOptions;

/// Held lock guard; released on drop.
pub struct StateLock {
    _file: std::fs::File,
}

/// Acquire the global mutation lock for `state_dir`.
pub fn acquire(state_dir: &std::path::Path) -> Result<StateLock, String> {
    std::fs::create_dir_all(state_dir).map_err(|e| format!("create state dir: {e:?}"))?;
    let path = state_dir.join(".lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| format!("open lock file: {e:?}"))?;
    {
        use fs2::FileExt;
        file.try_lock_exclusive().map_err(|_| {
            "another configctl mutation is already running (state lock held)".to_string()
        })?;
    }
    Ok(StateLock { _file: file })
}
