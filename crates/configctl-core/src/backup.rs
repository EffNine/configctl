//! Content-addressed backup store (P4; rollback reads in P7).
//!
//! Backups live under `<state>/backups/objects/<sha256>` with `0600`
//! permissions. They hold previous file bytes so failed or unwanted applies
//! can be restored. Secret values are never backed up by design: configctl
//! manages references, and managed files are dotfiles — but if a managed file
//! happens to contain secret-like text, the backup is still stored `0600` and
//! the limitation is documented (see THREAT_MODEL T13).

/// Validate a backup sha (`[0-9a-f]{64}`).
pub fn validate_sha(sha: &str) -> Result<(), String> {
    if sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!("invalid backup sha: {sha:?}"))
    }
}

fn object_path(state_dir: &std::path::Path, sha: &str) -> std::path::PathBuf {
    state_dir
        .join("backups/objects")
        .join(&sha[..2])
        .join(&sha[2..])
}

/// Store content, returning its sha256. Idempotent: existing objects are kept.
pub fn put(state_dir: &std::path::Path, content: &[u8]) -> Result<String, String> {
    let sha = crate::hash::file_content_hash(content);
    let dest = object_path(state_dir, &sha);
    if dest.exists() {
        return Ok(sha);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create backup dir: {e:?}"))?;
    }
    // Atomic write: temp + rename.
    let tmp = dest.with_extension("tmp-backup");
    std::fs::write(&tmp, content).map_err(|e| format!("write backup: {e:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &dest).map_err(|e| format!("commit backup: {e:?}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
    }
    Ok(sha)
}

/// Fetch backup content by sha.
pub fn get(state_dir: &std::path::Path, sha: &str) -> Result<Vec<u8>, String> {
    validate_sha(sha)?;
    let dest = object_path(state_dir, sha);
    std::fs::read(&dest).map_err(|e| format!("read backup {sha}: {e:?}"))
}
