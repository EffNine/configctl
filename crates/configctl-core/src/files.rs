//! Safe file capture: validate-then-copy with atomic writes.
//!
//! Never blindly copies. Before any byte is copied:
//!
//! 1. the source path is resolved safely (no symlink traversal),
//! 2. symlinks are rejected (P0 requires rejection at capture),
//! 3. the source must live inside an approved capture root,
//! 4. the file type must be a regular file,
//! 5. the size must be within limits,
//! 6. permissions are recorded,
//! 7. secret-bearing content is excluded (never copied),
//! 8. bytes are copied only after all validation passes.
//!
//! Generated artifacts use atomic writes (temp file + rename) and never
//! overwrite arbitrary user files: only paths inside the explicit output
//! directory are created.

use std::path::{Path, PathBuf};

/// Maximum file payload accepted for capture (matches P1 `max_file_bytes`).
pub const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Outcome of validating one candidate file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDecision {
    /// Safe to copy.
    Capture,
    /// Excluded with a machine-readable reason (`excluded_*`, `redacted_*`,
    /// `unsupported_*`, `unknown_*`).
    Skip { reason: String },
}

/// Validate one candidate source file.
///
/// - `source`: absolute candidate path.
/// - `approved_roots`: absolute approved capture roots (scan roots + `$HOME`);
///   the source (or its parent) must live inside one of them.
/// - `size_cap`: maximum accepted bytes.
pub fn decide_file(source: &Path, approved_roots: &[PathBuf], size_cap: u64) -> FileDecision {
    // 1. Symlink rejection: `symlink_metadata` never follows.
    let meta = match std::fs::symlink_metadata(source) {
        Ok(m) => m,
        Err(e) => {
            return FileDecision::Skip {
                reason: format!("unknown_unreadable: {e:?}"),
            };
        }
    };
    if meta.file_type().is_symlink() {
        return FileDecision::Skip {
            reason: "unsupported_symlink: source is a symlink".into(),
        };
    }
    // 2. Must be a regular file.
    if !meta.file_type().is_file() {
        return FileDecision::Skip {
            reason: "unsupported_not_regular: not a regular file".into(),
        };
    }
    // 3. Approved-root containment (lexical + canonical parent check).
    if !inside_any_root(source, approved_roots) {
        return FileDecision::Skip {
            reason: "excluded_outside_roots: source outside approved capture roots".into(),
        };
    }
    // 4. Size limit.
    if meta.len() > size_cap {
        return FileDecision::Skip {
            reason: format!(
                "excluded_oversized: {} bytes exceeds {size_cap}-byte cap",
                meta.len()
            ),
        };
    }
    // 5. Read + secret screening (bytes held only for this check; secret
    //    values are never logged or persisted).
    let bytes = match std::fs::read(source) {
        Ok(b) => b,
        Err(e) => {
            return FileDecision::Skip {
                reason: format!("unknown_unreadable: {e:?}"),
            };
        }
    };
    if bytes.len() as u64 > size_cap {
        return FileDecision::Skip {
            reason: "excluded_oversized: file grew beyond cap".into(),
        };
    }
    if looks_secret_bearing(&bytes) {
        return FileDecision::Skip {
            reason:
                "redacted_secret_content: file appears to contain secret material; payload excluded"
                    .into(),
        };
    }
    FileDecision::Capture
}

/// True when `path` is inside (or equal to) any of `roots`.
///
/// Uses canonicalized parents where possible so `..` tricks and symlink
/// parents cannot escape; falls back to a lexical prefix check when
/// canonicalization fails (best-effort, fail-closed: no root match ⇒ reject).
pub fn inside_any_root(path: &Path, roots: &[PathBuf]) -> bool {
    // Canonicalize the file's parent (cheap, no content read).
    let parent = path.parent().unwrap_or(Path::new("/"));
    let canon_parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    for root in roots {
        let canon_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
        if canon_parent.starts_with(&canon_root) {
            // Also require the file itself to be lexically inside the root
            // (defense in depth against `..` in the final component).
            if !path_components_escape(path) {
                return true;
            }
        }
    }
    false
}

fn path_components_escape(p: &Path) -> bool {
    p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// Heuristic: does raw file content look secret-bearing?
///
/// Conservative byte scan (no regex engine): PEM markers, known token
/// prefixes, and `password|secret` assignments with non-trivial values.
/// Operates on lossy-UTF8 text; binary files are not secret-bearing by this
/// check (they are still only copied when allowlisted by name).
fn looks_secret_bearing(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("BEGIN PRIVATE KEY")
        || text.contains("BEGIN RSA PRIVATE KEY")
        || text.contains("BEGIN OPENSSH PRIVATE KEY")
    {
        return true;
    }
    for prefix in [
        "sk-",
        "ghp_",
        "gho_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "sk_live_",
        "sk_test_",
        "AKIA",
        "ASIA",
    ] {
        // Require the prefix plus a plausible token tail to avoid flagging
        // prose that merely mentions a prefix.
        for token in text.split_whitespace() {
            if token.starts_with(prefix) && token.len() > prefix.len() + 8 {
                return true;
            }
        }
    }
    // `password|passwd|secret\s*[:=]\s*\S{4,}` (case-insensitive, line-wise).
    for line in text.lines() {
        let lower = line.to_lowercase();
        if (lower.contains("password") || lower.contains("passwd") || lower.contains("secret"))
            && (line.contains('=') || line.contains(':'))
        {
            // Value part non-trivial?
            let val = line
                .split(['=', ':'])
                .next_back()
                .unwrap_or("")
                .trim()
                .trim_matches(|c| c == '"' || c == '\'');
            if val.len() >= 4
                && !val.eq_ignore_ascii_case("true")
                && !val.eq_ignore_ascii_case("false")
            {
                return true;
            }
        }
    }
    false
}

/// Record the Unix permission bits as a 4-digit octal string (`"0600"`).
#[cfg(unix)]
pub fn mode_string(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::PermissionsExt;
    format!("{:04o}", meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
pub fn mode_string(_meta: &std::fs::Metadata) -> String {
    "0644".into()
}

/// Write `bytes` atomically to `dest`: create parent dirs, write to a temp
/// file in the same directory, `fsync`, rename, fsync the directory.
///
/// Refuses to write outside `bundle_dir` (fail-closed).
pub fn atomic_write_inside(bundle_dir: &Path, dest: &Path, bytes: &[u8]) -> Result<(), String> {
    let canon_bundle =
        std::fs::canonicalize(bundle_dir).unwrap_or_else(|_| bundle_dir.to_path_buf());
    // Lexical containment first (cheap fail-closed gate).
    if !dest.starts_with(&canon_bundle) && dest != canon_bundle {
        // `dest` may not exist yet; check its parent instead.
        if let Some(parent) = dest.parent() {
            // Walk up until an existing ancestor to canonicalize.
            let mut anc = parent;
            let mut found: Option<PathBuf> = None;
            loop {
                if anc.exists() {
                    found = std::fs::canonicalize(anc).ok();
                    break;
                }
                match anc.parent() {
                    Some(p) => anc = p,
                    None => break,
                }
            }
            if let Some(canon_anc) = found {
                if !canon_anc.starts_with(&canon_bundle) && canon_anc != canon_bundle {
                    return Err(format!(
                        "refusing to write outside bundle: {}",
                        dest.display()
                    ));
                }
            } else if !parent.starts_with(bundle_dir) {
                return Err(format!(
                    "refusing to write outside bundle: {}",
                    dest.display()
                ));
            }
        } else {
            return Err(format!(
                "refusing to write outside bundle: {}",
                dest.display()
            ));
        }
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create parent {}: {e:?}", parent.display()))?;
    }
    // Temp file in the same directory for an atomic rename.
    let tmp = dest.with_extension("tmp-capture");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write temp {}: {e:?}", tmp.display()))?;
    // Best-effort fsync of the temp file.
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp, dest).map_err(|e| format!("rename to {}: {e:?}", dest.display()))?;
    // Best-effort fsync of the parent directory.
    if let Some(parent) = dest.parent() {
        if let Ok(f) = std::fs::File::open(parent) {
            let _ = f.sync_all();
        }
    }
    Ok(())
}

/// Copy a validated source file into the bundle atomically.
///
/// Returns the recorded mode string.
pub fn copy_into_bundle(source: &Path, bundle_dir: &Path, rel: &str) -> Result<String, String> {
    let dest = bundle_dir.join(rel);
    let meta = std::fs::symlink_metadata(source)
        .map_err(|e| format!("metadata {}: {e:?}", source.display()))?;
    let mode = mode_string(&meta);
    let bytes = std::fs::read(source).map_err(|e| format!("read {}: {e:?}", source.display()))?;
    atomic_write_inside(bundle_dir, &dest, &bytes)?;
    // Restrict payload permissions to owner-only when the source was
    // owner-only (never broaden).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode` is an octal string (`"0644"`); always parse as octal —
        // never as decimal (a decimal parse of `644` would yield
        // owner-unreadable permissions).
        let digits = mode.trim_start_matches('0');
        let digits = if digits.is_empty() { "0" } else { digits };
        if let Ok(bits) = u32::from_str_radix(digits, 8) {
            let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(bits & 0o7777));
        }
    }
    Ok(mode)
}
