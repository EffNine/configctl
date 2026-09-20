//! Safe Git configuration metadata capture (read-only).
//!
//! Records allowlisted, non-credential Git settings only:
//!
//! - `user.name`, `user.email`
//! - `credential.helper` (metadata — the helper name, never stored creds)
//! - `core.excludesfile`, `init.defaultbranch`
//! - `alias.*` (command shortcuts; values are shell snippets the user wrote,
//!   recorded as-is — they are config, not credentials)
//! - `commit.gpgsign`, `gpg.format`
//!
//! Denied (never captured): `credential.*` contents, `http.*` (may embed
//! tokens), `url.*` (may embed tokens), and any key whose value looks
//! secret-bearing. Uses fixed argv via [`CommandRunner`]; never extracts
//! credential contents.

use crate::command::{CommandRequest, CommandRunner};
use crate::profile::GitConfig;

/// Capture Git metadata via `git config --global --list`.
///
/// Returns `None` when git is unavailable (profile then omits `[git]` and the
/// summary marks git `unknown`).
pub fn capture_git(runner: &dyn CommandRunner) -> Option<GitConfig> {
    let req = CommandRequest::new("git", ["config", "--global", "--list"]).output_cap(32 * 1024);
    let out = match runner.run(&req) {
        Ok(o) if o.status == Some(0) => o,
        _ => return None,
    };
    let mut cfg = GitConfig::default();
    for line in out.stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(eq) = line.find('=') else { continue };
        let key = line[..eq].trim().to_lowercase();
        let value = line[eq + 1..].trim().to_string();
        if value.is_empty() || value.contains('\0') {
            continue;
        }
        // Deny credential-bearing scopes outright.
        if key.starts_with("credential.") || key.starts_with("http.") || key.starts_with("url.") {
            // `credential.helper` is the single allowed exception (metadata).
            if key != "credential.helper" {
                continue;
            }
        }
        match key.as_str() {
            "user.name" => cfg.user_name = Some(value),
            "user.email" => cfg.user_email = Some(value),
            "credential.helper" => cfg.credential_helper = Some(value),
            "core.excludesfile" => cfg.excludes_file = Some(value),
            "init.defaultbranch" => cfg.default_branch = Some(value),
            "commit.gpgsign" => {
                cfg.commit_gpgsign = Some(matches!(
                    value.to_lowercase().as_str(),
                    "true" | "yes" | "1" | "on"
                ));
            }
            "gpg.format" => cfg.gpg_format = Some(value),
            k if k.starts_with("alias.") => {
                let alias = k.strip_prefix("alias.").unwrap_or(k).to_string();
                // Alias names are simple; reject control characters.
                if !alias.is_empty()
                    && !alias.contains('\0')
                    && !alias.contains('\n')
                    && alias.len() <= 64
                {
                    cfg.aliases.insert(alias, value);
                }
            }
            _ => {}
        }
    }
    // If nothing allowlisted was found, still return Some (empty metadata is
    // meaningful: git exists but no relevant config). Callers distinguish
    // `None` (git unavailable) from empty.
    Some(cfg)
}
