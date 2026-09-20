//! Canonical hashing for plans, profiles, and observed state.
//!
//! All semantic hashes exclude informational timestamps (`created_at`,
//! `captured_at`). Hash input is canonical JSON (BTreeMap-ordered keys via
//! `serde_json::Value` object sorting is not automatic — instead we build the
//! canonical document explicitly with sorted arrays and maps, then hash the
//! UTF-8 bytes with SHA-256).

use sha2::{Digest, Sha256};

/// SHA-256 hex of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Canonical file-content identity: SHA-256 over the exact file bytes.
///
/// This is the ONLY hash that may be compared against observed file content
/// (`observe_file().content_hash`), plan `desired_after` for file ops, apply
/// postchecks, rollback guards, and verify/drift checks. All of those stages
/// hash the same canonical byte representation (the whole file, byte for
/// byte), so the comparison is like-for-like.
///
/// Never compare a file-content hash against a value-domain hash (e.g. an
/// env literal hash): different byte strings hash differently even under the
/// same algorithm, so a cross-domain comparison fails closed (always unequal)
/// and breaks legitimate rollback. See `env_value_hash` for the value domain.
pub fn file_content_hash(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// Canonical environment-literal identity: SHA-256 over the exact UTF-8
/// bytes of one variable value.
///
/// Value-domain only: compare literal-vs-literal (plan `desired_after` for
/// env ops, apply postchecks, rollback value guards). Never compare against
/// a file-content hash (see `file_content_hash`).
pub fn env_value_hash(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

/// SHA-256 hex of a UTF-8 string.
pub fn sha256_str(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

/// SHA-256 hex of a file's bytes (bounded read; errors propagate as strings).
pub fn sha256_file(path: &std::path::Path, cap: u64) -> Result<String, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("metadata {}: {e:?}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("not a regular file: {}", path.display()));
    }
    if meta.len() > cap {
        return Err(format!("file {} exceeds {cap}-byte cap", path.display()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e:?}", path.display()))?;
    if bytes.len() as u64 > cap {
        return Err(format!("file {} grew beyond cap", path.display()));
    }
    Ok(file_content_hash(&bytes))
}
