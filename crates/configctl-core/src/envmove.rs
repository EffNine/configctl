//! Assisted-manual move mode (v1.2 E5): eligibility + unified-diff patch emission.
//!
//! Mode 3 removes the now-shadowed original lines so the environment stops
//! being ambiguous. It is the only consolidation mode that can change shell
//! semantics, so it is deliberately **not an automatic apply path**: this
//! module only *assesses* eligibility and *renders* a unified diff. It never
//! writes to the machine (the CLI performs the patch-file write and the
//! adjacent timestamped backups), never evaluates shell, and never expands
//! anything. The existing conservative [`crate::envmap`] parser and secret
//! screen are reused unchanged.
//!
//! Eligibility: ALL of these must hold for one line, else it is reported
//! ineligible with an explicit reason:
//!
//! - the parser classified it `managed` (excludes `special`/PATH,
//!   `manual`/conditional/complex, `secret`, `structure`)
//! - it is not inside the configctl include marker block itself
//! - the variable exists in the profile `[environment]` literals AND its
//!   value is byte-for-byte the managed (canonical) value
//! - the file already carries the managed include block (so the managed value
//!   still wins after the old line is tombstoned)
//!
//! Fail-closed file rules (the whole file is refused with a reason):
//! symlinked rc files, non-regular files, files over [`MAX_RC_BYTES`],
/// non-UTF-8 bytes, CRLF line endings, and partial/spoofed marker blocks.
use std::collections::BTreeMap;
use std::path::Path;

use crate::envmap::{self, LineClass, SourceKind};

/// Upper bound for an rc file move mode will consider. Larger files are
/// refused rather than read fully (a truncating or partial read would
/// produce a patch that does not describe the real file).
pub const MAX_RC_BYTES: u64 = 1024 * 1024;

/// Shell startup files examined by move mode, in session read order. Same
/// participating families as mode 2 (`~/.xprofile` stays opt-out;
/// `environment.d` is a session artifact, not a shell rc file).
fn move_sources() -> [(SourceKind, u32); 5] {
    [
        (SourceKind::Bashrc, 1),
        (SourceKind::BashProfile, 2),
        (SourceKind::Profile, 3),
        (SourceKind::Zshrc, 4),
        (SourceKind::Zshenv, 5),
    ]
}

/// One line eligible for tombstoning. `original` is the raw source line; it
/// is present only for eligible (managed, non-secret) lines, so secret values
/// can never reach the patch renderer through this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibleLine {
    /// Portable locator (`~/.bashrc`).
    pub file: String,
    /// Diff path relative to `$HOME` (`.bashrc`), used in patch headers so
    /// `patch -p0` works when run from `$HOME`.
    pub rel: String,
    /// 1-based original line number.
    pub line: usize,
    /// Variable name (never a value).
    pub name: String,
    /// Raw source line text (no trailing newline).
    pub original: String,
}

/// One line that must stay where it is, with the explicit reason why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IneligibleLine {
    /// Portable locator (`~/.bashrc`).
    pub file: String,
    /// 1-based original line number.
    pub line: usize,
    /// Variable name or short structural token (never a value).
    pub name: String,
    /// Explicit reason (names only, never values).
    pub reason: String,
}

/// Per-file outcome: either assessed (with a content hash) or refused whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMoveInfo {
    /// Portable locator (`~/.bashrc`).
    pub file: String,
    /// Diff path relative to `$HOME`.
    pub rel: String,
    /// SHA-256 over the exact bytes read, when the file could be read.
    pub hash: Option<String>,
    /// `Some(reason)` when the whole file was refused fail-closed.
    pub refused: Option<String>,
}

/// Full point-in-time assessment for `$HOME`.
#[derive(Debug, Clone, Default)]
pub struct MoveAssessment {
    pub eligible: Vec<EligibleLine>,
    pub ineligible: Vec<IneligibleLine>,
    pub files: Vec<FileMoveInfo>,
    pub warnings: Vec<String>,
}

/// Why move mode cannot proceed at all (as opposed to per-line ineligibility).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveError {
    /// A profile literal trips the secret screen: hard error, names the
    /// variable only (never the value).
    SecretTrip(String),
    /// The canonical managed file is missing or does not match the profile:
    /// the profile is stale relative to the machine, so tombstoning would be
    /// a semantic change. Re-run mode 2 first.
    Precondition(String),
}

impl std::fmt::Display for MoveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MoveError::SecretTrip(name) => write!(
                f,
                "refusing: {name} is secret-like; it must stay a secret reference and can never be consolidated"
            ),
            MoveError::Precondition(msg) => write!(f, "{msg}"),
        }
    }
}

/// Assess every participating rc file under `home` against the profile's
/// `[environment]` literals (`entries`: non-secret `NAME -> VALUE` pairs).
///
/// Read-only: files are read, never written. Returns [`MoveError::SecretTrip`]
/// when a canonical value trips the secret screen, and
/// [`MoveError::Precondition`] when the on-disk canonical file is missing or
/// stale (move mode only makes sense after mode 2 was applied).
pub fn assess_move(home: &Path, entries: &[(String, String)]) -> Result<MoveAssessment, MoveError> {
    if let Some(name) = envmap::first_secret_like(entries) {
        return Err(MoveError::SecretTrip(name));
    }

    // The canonical file is the proof that the managed values are live: when
    // it is missing or stale, tombstoning an rc line would change semantics.
    let composed = envmap::canonical_env_file(entries);
    match std::fs::read(home.join(envmap::CANONICAL_REL)) {
        Err(_) => {
            return Err(MoveError::Precondition(format!(
                "no canonical ~/{} yet; run `configctl env consolidate` (mode include) and `configctl apply` first, then re-run move mode",
                envmap::CANONICAL_REL
            )));
        }
        Ok(current) if current != composed.as_bytes() => {
            return Err(MoveError::Precondition(format!(
                "canonical ~/{} differs from the profile; re-run `configctl env consolidate` (mode include) and `configctl apply` first, then re-run move mode",
                envmap::CANONICAL_REL
            )));
        }
        Ok(_) => {}
    }

    let map: BTreeMap<&str, &str> = entries
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let mut out = MoveAssessment::default();
    for (kind, order) in move_sources() {
        let Some(rel) = kind.rel_path() else {
            continue;
        };
        let abs = home.join(rel);
        if !abs.exists() {
            continue;
        }
        assess_file(&abs, rel, kind, order, &map, &mut out);
    }
    out.eligible
        .sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    out.ineligible
        .sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    out.files.sort_by(|a, b| a.file.cmp(&b.file));
    Ok(out)
}

fn assess_file(
    abs: &Path,
    rel: &str,
    kind: SourceKind,
    order: u32,
    entries: &BTreeMap<&str, &str>,
    out: &mut MoveAssessment,
) {
    let file = format!("~/{rel}");
    let mut info = FileMoveInfo {
        file: file.clone(),
        rel: rel.to_string(),
        hash: None,
        refused: None,
    };
    let mut refuse = |info: &mut FileMoveInfo, reason: String| {
        info.refused = Some(reason.clone());
        out.ineligible.push(IneligibleLine {
            file: info.file.clone(),
            line: 0,
            name: "<file>".into(),
            reason,
        });
        out.files.push(info.clone());
    };

    let meta = match std::fs::symlink_metadata(abs) {
        Ok(m) => m,
        Err(_) => {
            refuse(&mut info, format!("{file} cannot be read; refusing"));
            return;
        }
    };
    if meta.file_type().is_symlink() {
        refuse(&mut info, format!("{file} is a symlink; refusing"));
        return;
    }
    if !meta.file_type().is_file() {
        refuse(&mut info, format!("{file} is not a regular file; refusing"));
        return;
    }
    if meta.len() > MAX_RC_BYTES {
        refuse(
            &mut info,
            format!("{file} is larger than {MAX_RC_BYTES} bytes; refusing to describe it"),
        );
        return;
    }
    let bytes = match std::fs::read(abs) {
        Ok(b) => b,
        Err(_) => {
            refuse(&mut info, format!("{file} cannot be read; refusing"));
            return;
        }
    };
    if bytes.len() as u64 > MAX_RC_BYTES {
        refuse(
            &mut info,
            format!("{file} grew beyond {MAX_RC_BYTES} bytes; refusing"),
        );
        return;
    }
    let content = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => {
            refuse(&mut info, format!("{file} is not valid UTF-8; refusing"));
            return;
        }
    };
    if content.contains('\r') {
        refuse(
            &mut info,
            format!("{file} has CRLF line endings; refusing (fail closed)"),
        );
        return;
    }
    info.hash = Some(crate::hash::file_content_hash(&bytes));

    // Marker-block analysis: exactly one well-formed block, or none. Anything
    // else (partial block, duplicated or spoofed markers) fails closed.
    let mut begins = Vec::new();
    let mut ends = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let t = line.trim();
        if t == envmap::INCLUDE_BEGIN {
            begins.push(idx + 1);
        } else if t == envmap::INCLUDE_END {
            ends.push(idx + 1);
        }
    }
    let has_block = !begins.is_empty() || !ends.is_empty();
    let block_range: Option<std::ops::Range<usize>> = if !has_block {
        None
    } else if begins.len() == 1 && ends.len() == 1 && begins[0] < ends[0] {
        Some(begins[0]..ends[0] + 1)
    } else {
        refuse(
            &mut info,
            format!("{file} has a partial or spoofed marker block; refusing"),
        );
        return;
    };

    let raw_lines: Vec<&str> = content.lines().collect();
    let source = envmap::parse_source(&file, content, kind, order);
    for d in &source.declarations {
        if let Some(range) = &block_range {
            if range.contains(&d.line) {
                out.ineligible.push(IneligibleLine {
                    file: file.clone(),
                    line: d.line,
                    name: d.name.clone(),
                    reason: "inside the managed include block; leave it alone".into(),
                });
                continue;
            }
        }
        match d.class {
            LineClass::Special => out.ineligible.push(IneligibleLine {
                file: file.clone(),
                line: d.line,
                name: d.name.clone(),
                reason: "behaviour-defining variable; never moved".into(),
            }),
            LineClass::Manual => out.ineligible.push(IneligibleLine {
                file: file.clone(),
                line: d.line,
                name: d.name.clone(),
                reason: format!(
                    "left alone ({})",
                    d.reason.as_deref().unwrap_or("conditional")
                ),
            }),
            LineClass::Secret => out.ineligible.push(IneligibleLine {
                file: file.clone(),
                line: d.line,
                name: d.name.clone(),
                reason: "looks like a secret; managed by reference, never moved".into(),
            }),
            LineClass::Structure => out.ineligible.push(IneligibleLine {
                file: file.clone(),
                line: d.line,
                name: d.name.clone(),
                reason: "shell structure, not a setting".into(),
            }),
            LineClass::Managed => {
                let Some(want) = entries.get(d.name.as_str()) else {
                    out.ineligible.push(IneligibleLine {
                        file: file.clone(),
                        line: d.line,
                        name: d.name.clone(),
                        reason:
                            "not in the profile [environment]; no managed value to consolidate to"
                                .into(),
                    });
                    continue;
                };
                if d.value.as_deref() != Some(*want) {
                    out.ineligible.push(IneligibleLine {
                        file: file.clone(),
                        line: d.line,
                        name: d.name.clone(),
                        reason: "value differs from the managed value; removing it would change semantics"
                            .into(),
                    });
                    continue;
                }
                if !has_block {
                    out.ineligible.push(IneligibleLine {
                        file: file.clone(),
                        line: d.line,
                        name: d.name.clone(),
                        reason: "managed include block not present in this file; apply `env consolidate` (mode include) first"
                            .into(),
                    });
                    continue;
                }
                out.eligible.push(EligibleLine {
                    file: file.clone(),
                    rel: rel.to_string(),
                    line: d.line,
                    name: d.name.clone(),
                    original: raw_lines
                        .get(d.line.saturating_sub(1))
                        .unwrap_or(&"")
                        .to_string(),
                });
            }
        }
    }
    out.files.push(info);
}

/// Tombstone comment for one eligible line. Deterministic in `name`: the
/// same name always renders the same patch body, so re-emission is idempotent
/// across seconds. The emission timestamp lives only in the patch-file
/// header (see [`build_patch`]), never in per-line tombstones.
pub fn tombstone_comment(name: &str) -> String {
    format!("# configctl-move {name} consolidated to ~/.config/configctl/env.sh")
}

/// Prefix of the single patch-header line carrying the emission timestamp.
/// Re-emit idempotency compares patch bodies with this line stripped, so the
/// header timestamp never forces a false conflict.
pub const PATCH_HEADER_PREFIX: &str = "# Generated ";

/// Resolve where the timestamped backup for `rel` (e.g. `.bashrc`) goes.
/// With `backup_dir` all backups live there as
/// `<rc-basename>.configctl-bak-<timestamp>`; without it the backup lands
/// adjacent to the rc file (backward compatible).
pub fn backup_path_for(
    home: &Path,
    rel: &str,
    timestamp_secs: i64,
    backup_dir: Option<&Path>,
) -> std::path::PathBuf {
    match backup_dir {
        Some(dir) => {
            let basename = Path::new(rel)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| rel.to_string());
            dir.join(format!("{basename}.configctl-bak-{timestamp_secs}"))
        }
        None => {
            let abs = home.join(rel);
            abs.with_extension(format!(
                "{}configctl-bak-{timestamp_secs}",
                abs.extension()
                    .map(|x| format!("{}.", x.to_string_lossy()))
                    .unwrap_or_default()
            ))
        }
    }
}

/// Patch body with the single `# Generated …` header timestamp line removed.
/// Used to decide re-emit idempotency: same eligible set + same file hashes
/// means the same body, even when the header timestamp differs.
pub fn patch_body_without_header(patch: &str) -> String {
    patch
        .lines()
        .filter(|l| !l.starts_with(PATCH_HEADER_PREFIX))
        .collect::<Vec<_>>()
        .join("\n")
}

/// True when two emitted patches describe the same change (eligible set +
/// file hashes identical), ignoring only the header timestamp line.
pub fn patches_equivalent(a: &str, b: &str) -> bool {
    patch_body_without_header(a) == patch_body_without_header(b)
}

/// Render the assisted-manual patch for an assessment as a unified diff, so
/// `patch -p0 < file` (run from `$HOME`) applies it.
///
/// Pure and deterministic in the eligible set: the same assessment always
/// yields the same body. The only timestamp-bearing line is the single
/// `# Generated <UTC> by configctl env consolidate --mode move` header;
/// per-line tombstones are deterministic (see [`tombstone_comment`]). One
/// hunk per eligible line (`-1/+2`), with `+` line numbers adjusted for
/// earlier tombstones in the same file. Per-file notes name the content hash
/// and the shadowing fact; the leading comment block carries the
/// point-in-time warning. No values appear except the raw eligible (managed,
/// non-secret) source lines being tombstoned.
pub fn build_patch(assessment: &MoveAssessment, timestamp_secs: i64) -> String {
    let mut s = format!(
        "# Generated {timestamp_secs} by configctl env consolidate --mode move\n\
         # configctl move patch (assisted manual, mode 3) — review every hunk before applying.\n\
         # Point-in-time: re-run `configctl env consolidate --mode move --dry-run` before applying;\n\
         # refuse to apply when the file hashes below no longer match.\n\
         # Apply from $HOME with: patch -p0 < <this file>\n\
         # `configctl rollback` cannot restore an out-of-band patch; keep the printed backups.\n",
    );
    // Group eligible lines per file in diff order.
    let mut by_file: BTreeMap<&str, Vec<&EligibleLine>> = BTreeMap::new();
    for e in &assessment.eligible {
        by_file.entry(e.rel.as_str()).or_default().push(e);
    }
    let hash_of = |rel: &str| {
        assessment
            .files
            .iter()
            .find(|f| f.rel == rel)
            .and_then(|f| f.hash.clone())
            .unwrap_or_else(|| "unknown".into())
    };
    for (rel, lines) in &by_file {
        let file = format!("~/{rel}");
        let hash = hash_of(rel);
        s.push_str(&format!(
            "\nFile {file} (sha256 {hash}): {} line(s) eligible; \
             each old line below is now overridden by the managed value via the include block.\n",
            lines.len()
        ));
        s.push_str(&format!(
            "--- {rel}\t{hash}\n+++ {rel}\t{hash}.tombstoned\n"
        ));
        for (i, e) in lines.iter().enumerate() {
            let plus_line = e.line + i;
            s.push_str(&format!("@@ -{},1 +{},2 @@\n", e.line, plus_line));
            s.push_str(&format!("-{}\n", e.original));
            s.push_str(&format!("+{}\n", tombstone_comment(&e.name)));
            s.push_str(&format!("+# {}\n", e.original));
        }
    }
    if by_file.is_empty() {
        s.push_str("\nNo eligible lines: nothing to tombstone.\n");
    } else {
        let files = by_file.len();
        let lines: usize = by_file.values().map(Vec::len).sum();
        s.push_str(&format!(
            "\nEnd of patch: {lines} line(s) in {files} file(s).\n"
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tombstones_are_deterministic() {
        assert_eq!(tombstone_comment("EDITOR"), tombstone_comment("EDITOR"));
        assert_ne!(tombstone_comment("EDITOR"), tombstone_comment("LANG"));
        // No timestamp leaks into the per-line tombstone.
        assert!(!tombstone_comment("EDITOR").contains('@'));
    }

    #[test]
    fn backup_paths_resolve_both_modes() {
        let home = Path::new("/home/user");
        // Adjacent (default): next to the rc file.
        let adjacent = backup_path_for(home, ".bashrc", 42, None);
        assert_eq!(adjacent, home.join(".bashrc.configctl-bak-42"));
        // Directed: basename preserved inside the backup dir.
        let dir = Path::new("/tmp/backups");
        let directed = backup_path_for(home, ".bashrc", 42, Some(dir));
        assert_eq!(directed, dir.join(".bashrc.configctl-bak-42"));
        let directed_z = backup_path_for(home, ".zshrc", 7, Some(dir));
        assert_eq!(directed_z, dir.join(".zshrc.configctl-bak-7"));
    }

    #[test]
    fn patch_bodies_are_stable_across_timestamps() {
        // Two builds with different header timestamps share one body.
        let body_a = "# Generated 42 by configctl env consolidate --mode move\n-foo\n";
        let body_b = "# Generated 43 by configctl env consolidate --mode move\n-foo\n";
        assert!(patches_equivalent(body_a, body_b));
        assert_ne!(body_a, body_b);
        assert_eq!(
            patch_body_without_header(body_a),
            patch_body_without_header(body_b)
        );
        // A genuinely different body is not equivalent.
        assert!(!patches_equivalent(
            body_a,
            "# Generated 43 by configctl env consolidate --mode move\n-bar\n"
        ));
    }
}
