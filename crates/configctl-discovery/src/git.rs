//! Git tracking detection via `CommandRunner` (fixed argv, no shell).
//!
//! Detects whether files are tracked/untracked/ignored. Never extracts
//! credential contents. Read-only.

use crate::env::GitStatus;
use configctl_core::command::{CommandRequest, CommandRunner};
use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;

/// Resolve the git toplevel for a directory (if any) using
/// `git rev-parse --show-toplevel`. `start` must be a directory.
pub fn find_git_root(runner: &dyn CommandRunner, start: &Path) -> Result<Option<PathBuf>, String> {
    let req = CommandRequest::new("git", ["rev-parse", "--show-toplevel"])
        .cwd(start)
        .output_cap(4096);
    match runner.run(&req) {
        Ok(out) if out.status == Some(0) => {
            let line = out.stdout.lines().next().unwrap_or("").trim();
            if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(PathBuf::from(line)))
            }
        }
        Ok(_) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// The git root containing `dir`, found by walking up through parents.
/// Returns `None` when no `.git` is reachable from `dir`.
pub fn git_root_for_dir(runner: &dyn CommandRunner, dir: &Path) -> Option<PathBuf> {
    let mut d = Some(dir.to_path_buf());
    while let Some(cur) = d {
        match find_git_root(runner, &cur) {
            Ok(Some(root)) => return Some(root),
            Ok(None) => {}
            Err(_) => {}
        }
        d = cur.parent().map(PathBuf::from);
    }
    None
}

/// Check git tracking status of a set of files.
///
/// Returns a map of path-string → GitStatus.
pub fn check_tracking(
    runner: &dyn CommandRunner,
    git_root: &Path,
    files: &[PathBuf],
) -> std::collections::BTreeMap<String, GitStatus> {
    let mut result: std::collections::BTreeMap<String, GitStatus> = files
        .iter()
        .map(|f| (f.to_string_lossy().into_owned(), GitStatus::Unknown))
        .collect();

    if files.is_empty() {
        return result;
    }

    // One combined `git status --porcelain=v1 -- <paths...>` call for the
    // files that have changes.
    let mut args: Vec<String> = vec!["status".into(), "--porcelain=v1".into(), "--".into()];
    for f in files {
        let rel = f.strip_prefix(git_root).unwrap_or(f);
        args.push(rel.to_string_lossy().into_owned());
    }
    let req = CommandRequest::new("git", args.as_slice())
        .cwd(git_root)
        .output_cap(16384);
    if let Ok(out) = runner.run(&req) {
        for line in out.stdout.lines() {
            if line.len() < 4 {
                continue;
            }
            let xy: Vec<char> = line[..2].chars().collect();
            let x = xy[0];
            let y = xy[1];
            let path_part = line[3..].trim().to_string();
            let resolved = git_root.join(&path_part);
            let key = resolved.to_string_lossy().into_owned();

            let status = if x == '?' && y == '?' {
                GitStatus::Untracked
            } else {
                GitStatus::Tracked
            };

            if let Some(slot) = result.get_mut(&key) {
                if *slot == GitStatus::Unknown {
                    *slot = status;
                }
            }
        }
    }

    // Files absent from `git status` output are tracked with no changes:
    // confirm with a bounded `git ls-files` call.
    let remaining: Vec<&PathBuf> = files
        .iter()
        .filter(|f| result.get(&f.to_string_lossy().into_owned()) == Some(&GitStatus::Unknown))
        .collect();
    if !remaining.is_empty() {
        let mut ls_args: Vec<String> = vec!["ls-files".into(), "--".into()];
        for f in &remaining {
            let rel = f.strip_prefix(git_root).unwrap_or(f);
            ls_args.push(rel.to_string_lossy().into_owned());
        }
        let req2 = CommandRequest::new("git", ls_args.as_slice())
            .cwd(git_root)
            .output_cap(8192);
        if let Ok(out2) = runner.run(&req2) {
            let listed: BTreeSet<String> = out2
                .stdout
                .lines()
                .map(|l| git_root.join(l.trim()).to_string_lossy().into_owned())
                .collect();
            for f in &remaining {
                let key = f.to_string_lossy().into_owned();
                if listed.contains(&key) {
                    result.insert(key, GitStatus::Tracked);
                }
            }
        }
    }

    // Check ignored for untracked files.
    for f in files {
        let key = f.to_string_lossy().into_owned();
        if result.get(&key) == Some(&GitStatus::Untracked) {
            let rel = f
                .strip_prefix(git_root)
                .unwrap_or(f)
                .to_string_lossy()
                .into_owned();
            let mut args: Vec<String> = vec!["check-ignore".into(), "-q".into(), "--".into()];
            args.push(rel);
            let req2 = CommandRequest::new("git", args.as_slice())
                .cwd(git_root)
                .output_cap(4096);
            if let Ok(out2) = runner.run(&req2) {
                if out2.status == Some(0) {
                    result.insert(key, GitStatus::Ignored);
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use configctl_core::command::{CommandOutput, FakeCommandRunner};

    fn out(status: i32, stdout: &str) -> CommandOutput {
        CommandOutput {
            status: Some(status),
            stdout: stdout.to_string(),
            ..CommandOutput::default()
        }
    }

    #[test]
    fn find_git_root_parses_show_toplevel() {
        let r = FakeCommandRunner::new();
        r.queue(out(0, "/home/u/proj\n"));
        let got = find_git_root(&r, Path::new("/home/u/proj/sub")).unwrap();
        assert_eq!(got, Some(PathBuf::from("/home/u/proj")));
    }

    #[test]
    fn find_git_root_returns_none_outside_a_repo() {
        let r = FakeCommandRunner::new();
        r.queue(out(128, "fatal: not a git repository\n"));
        assert_eq!(find_git_root(&r, Path::new("/tmp")).unwrap(), None);
    }

    #[test]
    fn git_root_for_dir_walks_up_to_the_repository() {
        let r = FakeCommandRunner::new();
        // First probe (the deep dir) is not a repo; the parent is.
        r.queue(out(128, ""));
        r.queue(out(0, "/repo\n"));
        let got = git_root_for_dir(&r, Path::new("/repo/sub"));
        assert_eq!(got, Some(PathBuf::from("/repo")));
    }

    #[test]
    fn check_tracking_classifies_untracked_tracked_and_unknown() {
        let root = Path::new("/repo");
        let untracked = root.join("new.txt");
        let tracked = root.join("src/main.rs");
        let unknown = root.join("target/debug/build");
        let files = vec![untracked.clone(), tracked.clone(), unknown.clone()];

        let r = FakeCommandRunner::new();
        // 1. `git status --porcelain=v1 -- <paths>`: only new.txt has changes.
        r.queue(out(0, "?? new.txt\n"));
        // 2. `git ls-files -- <remaining>`: only main.rs is tracked.
        r.queue(out(0, "src/main.rs\n"));
        // 3. `git check-ignore -q -- new.txt`: not ignored.
        r.queue(out(1, ""));

        let got = check_tracking(&r, root, &files);
        assert_eq!(
            got.get(&untracked.to_string_lossy().into_owned()),
            Some(&GitStatus::Untracked)
        );
        assert_eq!(
            got.get(&tracked.to_string_lossy().into_owned()),
            Some(&GitStatus::Tracked)
        );
        assert_eq!(
            got.get(&unknown.to_string_lossy().into_owned()),
            Some(&GitStatus::Unknown)
        );
    }

    #[test]
    fn check_tracking_marks_ignored_files() {
        let root = Path::new("/repo");
        let ignored = root.join("secret.env");
        let files = vec![ignored.clone()];

        let r = FakeCommandRunner::new();
        // 1. status reports it untracked.
        r.queue(out(0, "?? secret.env\n"));
        // 2. check-ignore says it is ignored (exit 0).
        r.queue(out(0, ""));

        let got = check_tracking(&r, root, &files);
        assert_eq!(
            got.get(&ignored.to_string_lossy().into_owned()),
            Some(&GitStatus::Ignored)
        );
    }
}
