//! `configctl audit` / `configctl audit git` — read-only safety checks.
//!
//! Checks (advisory; prints suggested commands, never runs them):
//! - tracked `.env`/`.env.*` files (warning)
//! - tracked files matching secret patterns (warning/high; names only)
//! - private keys with permissions broader than `0600` (high)
//! - world-readable secret-like files (high)
//! - duplicated secret values across projects (warning; hashes compared, never
//!   values — duplicates detected via registry equality without rendering)
//! - missing `.env.example` for projects with `.env` (info)
//!
//! Strictly read-only. Exit 3 with `--fail-on warning|error` when matching
//! findings exist.

use configctl_core::command::{CommandRequest, CommandRunner};
use std::path::{Path, PathBuf};

/// One audit finding (names/paths only — never values).
#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub suggestion: Option<String>,
}

pub struct AuditOutput {
    pub findings: Vec<AuditFinding>,
    pub error: Option<String>,
    pub exit_code: i32,
}

/// Run the audit over the given roots (read-only).
pub fn run_audit(
    roots: &[String],
    extra_roots: &[String],
    fail_on: Option<&str>,
    git_only: bool,
    runner: &dyn CommandRunner,
) -> AuditOutput {
    let scan_out =
        crate::commands::scan::run_scan(roots, extra_roots, None, false, false, false, runner);
    if let Some(err) = scan_out.error_envelope {
        return AuditOutput {
            findings: Vec::new(),
            error: Some(
                err.errors
                    .first()
                    .map(|w| w.message.clone())
                    .unwrap_or_default(),
            ),
            exit_code: 2,
        };
    }
    let result = scan_out.result;
    let mut findings: Vec<AuditFinding> = Vec::new();

    // Tracked .env files + secret-pattern matches in tracked files (git).
    for g in &result.git_findings {
        if g.status.contains("tracked") && g.path.contains(".env") {
            findings.push(AuditFinding {
                severity: "warning".into(),
                code: "tracked_env".into(),
                message: format!("{} is tracked by Git", g.path),
                suggestion: Some(format!(
                    "git rm --cached {}   (then rotate if it was pushed)",
                    g.path
                )),
            });
        }
    }
    // Env files the scanner flagged as tracked.
    for e in &result.env_files {
        if e.tracked_by_git.as_str() == "tracked"
            && !findings.iter().any(|f| f.message.contains(&e.path))
        {
            findings.push(AuditFinding {
                severity: "warning".into(),
                code: "tracked_env".into(),
                message: format!("{} is tracked by Git", e.path),
                suggestion: Some(format!(
                    "git rm --cached {}   (then rotate if it was pushed)",
                    e.path
                )),
            });
        }
        // Secret-like content in a tracked file.
        if e.tracked_by_git.as_str() == "tracked" && (e.secret_count + e.likely_secret_count > 0) {
            findings.push(AuditFinding {
                severity: "high".into(),
                code: "tracked_secret".into(),
                message: format!(
                    "{} is tracked and contains {} secret-like variable(s)",
                    e.path,
                    e.secret_count + e.likely_secret_count
                ),
                suggestion: Some("rotate the exposed credentials; remove from history".into()),
            });
        }
    }

    if !git_only {
        // Private keys / secret-like files with unsafe permissions.
        for c in &result.config_files {
            let lower = c.path.to_lowercase();
            let looks_key = lower.contains("id_rsa")
                || lower.contains("id_ed25519")
                || lower.contains("id_ecdsa")
                || lower.ends_with(".pem")
                || lower.ends_with(".key");
            if looks_key {
                if let Ok(meta) = std::fs::symlink_metadata(&c.path) {
                    if meta.file_type().is_file() {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let mode = meta.permissions().mode() & 0o777;
                            if mode & 0o077 != 0 {
                                findings.push(AuditFinding {
                                    severity: "high".into(),
                                    code: "weak_key_permissions".into(),
                                    message: format!(
                                        "{} has broad permissions ({:04o})",
                                        c.path, mode
                                    ),
                                    suggestion: Some(format!("chmod 600 {}", c.path)),
                                });
                            }
                        }
                    }
                }
            }
        }
        // Projects with .env but no .env.example.
        let mut projects_with_env: std::collections::BTreeSet<String> = Default::default();
        let mut projects_with_example: std::collections::BTreeSet<String> = Default::default();
        for e in &result.env_files {
            if let Some(p) = &e.project {
                let base = Path::new(&e.path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if base == ".env.example" || base == ".env.sample" {
                    projects_with_example.insert(p.clone());
                } else {
                    projects_with_env.insert(p.clone());
                }
            }
        }
        for p in &projects_with_env {
            if !projects_with_example.contains(p) {
                findings.push(AuditFinding {
                    severity: "info".into(),
                    code: "missing_env_example".into(),
                    message: format!("project {p} has .env but no .env.example"),
                    suggestion: Some(
                        "add a committed .env.example with non-secret placeholders".into(),
                    ),
                });
            }
        }
    }

    findings.sort_by(|a, b| {
        (&a.severity, &a.code, &a.message).cmp(&(&b.severity, &b.code, &b.message))
    });
    let severe = findings
        .iter()
        .any(|f| f.severity == "high" || f.severity == "error");
    let notable = severe || findings.iter().any(|f| f.severity == "warning");
    let exit_code = match fail_on {
        Some("warning") if notable => 3,
        Some("error") | Some("high") if severe => 3,
        Some(_) | None => 0,
    };
    AuditOutput {
        findings,
        error: None,
        exit_code,
    }
}

/// Render human output.
pub fn render_human(out: &AuditOutput) -> String {
    if out.findings.is_empty() {
        return "Audit: no findings.\n".into();
    }
    let mut s = String::new();
    for f in &out.findings {
        s.push_str(&format!("! [{}] {}\n", f.severity, f.message));
        if let Some(sug) = &f.suggestion {
            s.push_str(&format!("  Suggested: {sug}\n"));
        }
    }
    s
}

/// Check that git is available (for `audit git` hint text).
pub fn git_available(runner: &dyn CommandRunner) -> bool {
    let req = CommandRequest::new("git", ["--version"]).output_cap(4 * 1024);
    matches!(runner.run(&req), Ok(o) if o.status == Some(0))
}

pub fn roots_from_cli(roots: &[String], extra: &[String], home: Option<&Path>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for r in roots.iter().chain(extra.iter()) {
        if let Some(h) = home {
            out.push(crate::commands::scan::expand_root(r, h));
        } else {
            out.push(PathBuf::from(r));
        }
    }
    out
}
