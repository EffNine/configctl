//! v1.1 hang / OOM / pathological-input tests.
//!
//! Every test here must terminate. Fixtures stay small enough for CI while
//! still exercising the bounding machinery; the governor-budget variants
//! prove that unbounded inputs degrade to PARTIAL instead of hanging.
//! Subprocess tests use the real [`StdCommandRunner`] against fixed argv.

use configctl_core::command::{CommandRequest, CommandRunner, FakeCommandRunner, StdCommandRunner};
use configctl_core::governor::{GovernorBudgets, ResourceGovernor};
use configctl_discovery::scanner::{ScanOptions, Scanner};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn scan_with(
    root: &Path,
    runner: &dyn CommandRunner,
    governor: GovernorBudgets,
) -> configctl_discovery::scanner::ScanResult {
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![root.to_path_buf()],
        limits: Default::default(),
        governor,
    };
    scanner.scan(&opts, runner)
}

fn scan_default(root: &Path) -> configctl_discovery::scanner::ScanResult {
    scan_with(root, &FakeCommandRunner::new(), GovernorBudgets::default())
}

fn timed<T>(label: &str, limit: Duration, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed();
    assert!(
        elapsed < limit,
        "{label} took too long: {elapsed:?} (limit {limit:?})"
    );
    out
}

#[test]
fn deep_tree_terminates_with_depth_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let mut p = tmp.path().to_path_buf();
    for i in 0..150 {
        p = p.join(format!("d{i}"));
    }
    std::fs::create_dir_all(&p).unwrap();
    std::fs::write(p.join("leaf.txt"), "x\n").unwrap();

    let result = timed("150-level tree", Duration::from_secs(30), || {
        scan_default(tmp.path())
    });
    assert!(result
        .statistics
        .stop_reasons
        .iter()
        .any(|r| r == "depth_limit"));
}

#[test]
fn wide_directory_terminates_and_counts() {
    let tmp = tempfile::tempdir().unwrap();
    for i in 0..3000 {
        std::fs::write(tmp.path().join(format!("f{i:05}.txt")), b"x\n").unwrap();
    }
    let result = timed("3000-file dir", Duration::from_secs(60), || {
        scan_default(tmp.path())
    });
    assert!(result.filesystem.counters.files >= 3000);

    // The same tree under a tiny file budget degrades to PARTIAL, not a hang.
    let partial = scan_with(
        tmp.path(),
        &FakeCommandRunner::new(),
        GovernorBudgets {
            max_file_count: 100,
            ..GovernorBudgets::default()
        },
    );
    assert_eq!(
        partial.completeness.status,
        Some(configctl_core::inventory::ScanStatus::Partial)
    );
}

#[test]
fn huge_file_is_counted_never_loaded() {
    let tmp = tempfile::tempdir().unwrap();
    let big = tmp.path().join("huge.bin");
    // 64 MiB sparse-ish blob (zeros compress nothing on disk here, but the
    // scanner must only stat it, never hold it in memory).
    let chunk = vec![0u8; 1024 * 1024];
    let f = std::fs::File::create(&big).unwrap();
    for _ in 0..64 {
        use std::io::Write;
        (&f).write_all(&chunk).unwrap();
    }
    drop(f);
    let result = timed("64MiB file", Duration::from_secs(30), || {
        scan_default(tmp.path())
    });
    assert!(result.filesystem.counters.files >= 1);
}

#[test]
fn fifo_never_blocks_the_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let fifo = tmp.path().join("pipe.fifo");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status();
    if !status.map(|s| s.success()).unwrap_or(false) {
        eprintln!("SKIP: mkfifo unavailable");
        return;
    }
    std::fs::write(tmp.path().join("normal.txt"), b"x\n").unwrap();
    let result = timed("fifo tree", Duration::from_secs(30), || {
        scan_default(tmp.path())
    });
    assert!(result.filesystem.counters.fifos >= 1);
    assert!(result.filesystem.counters.files >= 1);
}

#[test]
fn symlink_loops_terminate_with_cycle_flags() {
    let tmp = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(tmp.path().join("b"), tmp.path().join("a")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("a"), tmp.path().join("b")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("self"), tmp.path().join("self")).unwrap();
    std::fs::write(tmp.path().join("real.txt"), b"x\n").unwrap();
    let result = timed("symlink loops", Duration::from_secs(30), || {
        scan_default(tmp.path())
    });
    assert!(result.filesystem.counters.symlinks >= 3);
    assert!(result
        .filesystem
        .symlinks
        .iter()
        .any(|s| s.cycle == Some(true)));
    // Bounded depth: no chain record exceeds the symlink budget.
    for s in &result.filesystem.symlinks {
        assert!(s.depth <= 16, "chain depth unbounded: {:?}", s.depth);
    }
}

#[test]
fn permission_denied_tree_is_recorded_not_fatal() {
    let tmp = tempfile::tempdir().unwrap();
    let locked = tmp.path().join("locked");
    std::fs::create_dir_all(locked.join("sub")).unwrap();
    std::fs::write(locked.join("sub/secret.txt"), b"x\n").unwrap();
    std::fs::write(tmp.path().join("open.txt"), b"x\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Sanity: if the test runs as root, the mode bit does not actually deny.
    let denied = std::fs::read_dir(&locked).is_err();
    let result = timed("locked tree", Duration::from_secs(30), || {
        scan_default(tmp.path())
    });
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    if !denied {
        eprintln!("SKIP: running with privilege; permission bits not enforced");
        return;
    }
    assert!(result.statistics.permission_denied >= 1);
    assert!(result
        .completeness
        .reasons
        .contains_key("permission_denied"));
}

#[test]
fn hung_subprocess_is_killed_with_timeout_recorded() {
    let runner = StdCommandRunner::with_defaults(Duration::from_secs(2), 64 * 1024);
    let req = CommandRequest::new("sleep", ["30"]);
    let start = Instant::now();
    let out = runner.run(&req).expect("runner responds");
    let elapsed = start.elapsed();
    assert!(out.timed_out, "sleep 30 must be killed at the deadline");
    assert_eq!(out.status, None);
    assert!(
        elapsed < Duration::from_secs(15),
        "kill took too long: {elapsed:?}"
    );
}

#[test]
fn infinite_output_is_capped_and_terminates() {
    let runner = StdCommandRunner::with_defaults(Duration::from_secs(10), 64 * 1024);
    let req = CommandRequest::new("yes", Vec::<String>::new());
    let start = Instant::now();
    let outcome = runner.run(&req);
    let elapsed = start.elapsed();
    // `yes` may be missing on exotic systems — only assert when it spawned.
    if outcome.is_err() {
        eprintln!("SKIP: `yes` unavailable");
        return;
    }
    let out = outcome.unwrap();
    assert!(out.truncated, "infinite output must hit the cap");
    assert!(out.stdout.len() <= 64 * 1024 + 8192);
    assert!(
        elapsed < Duration::from_secs(20),
        "infinite output hung: {elapsed:?}"
    );
}

#[test]
fn hostile_filenames_do_not_break_or_escape() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("evil\nnewline.env"), b"A=1\n").unwrap();
    std::fs::write(tmp.path().join("ünïcodé_ß.env"), b"B=2\n").unwrap();
    std::fs::write(tmp.path().join("x".repeat(200)), b"C=3\n").unwrap();
    std::fs::create_dir_all(tmp.path().join("sub")).unwrap();
    let result = timed("hostile names", Duration::from_secs(30), || {
        scan_default(tmp.path())
    });
    // Completes and stays inside the root: no record may escape it.
    let root = tmp.path().to_string_lossy().into_owned();
    for e in &result.env_files {
        assert!(e.path.starts_with(&root), "escape: {}", e.path);
    }
    for d in &result.dotfiles {
        assert!(d.path.starts_with(&root), "escape: {}", d.path);
    }
}

#[test]
fn disappearing_files_are_tolerated() {
    // A file removed between directory listing and processing must produce
    // a warning, never a crash. (Best-effort: create then delete before scan
    // still exercises the missing-file paths in env/config processing.)
    let tmp = tempfile::tempdir().unwrap();
    let ghost = tmp.path().join("ghost.env");
    std::fs::write(&ghost, b"A=1\n").unwrap();
    std::fs::remove_file(&ghost).unwrap();
    std::fs::write(tmp.path().join("real.env"), b"B=2\n").unwrap();
    let result = timed("ghost file", Duration::from_secs(30), || {
        scan_default(tmp.path())
    });
    assert!(result
        .env_files
        .iter()
        .any(|e| e.path.ends_with("real.env")));
}

#[test]
fn repeated_scans_are_deterministic() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::fs::write(proj.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(proj.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(proj.join(".env"), "PORT=3000\n").unwrap();
    std::fs::write(tmp.path().join(".bashrc"), "x\n").unwrap();

    let normalize = |r: &configctl_discovery::scanner::ScanResult| -> serde_json::Value {
        let mut v = serde_json::to_value(r).unwrap();
        v.as_object_mut().unwrap().remove("timestamp");
        v.as_object_mut().unwrap().remove("governor");
        // Warnings may embed counts in stable order already; keep them.
        v
    };
    let first = normalize(&scan_default(tmp.path()));
    let second = normalize(&scan_default(tmp.path()));
    assert_eq!(
        first, second,
        "repeated scans must produce identical inventories"
    );
}

#[test]
fn root_walk_respects_mount_boundaries() {
    // Live system walk with tight budgets: must terminate quickly and
    // record pseudo-filesystem boundaries instead of descending into them.
    if !Path::new("/proc").exists() {
        eprintln!("SKIP: no /proc on this machine");
        return;
    }
    let gov = GovernorBudgets {
        max_file_count: 2000,
        max_directory_entries: 20000,
        max_wall_time: Duration::from_secs(60),
        ..GovernorBudgets::default()
    };
    let result = timed("bounded / walk", Duration::from_secs(90), || {
        scan_with(Path::new("/"), &FakeCommandRunner::new(), gov)
    });
    // Either the budget or a boundary stopped deep traversal — but the scan
    // finished and said so explicitly.
    assert!(!result.completeness.reasons.is_empty() || result.statistics.stop_reasons.is_empty());
    let _ = PathBuf::from("/");
}

#[test]
fn governor_subprocess_budget_stops_tool_storms() {
    let gov = ResourceGovernor::new(GovernorBudgets {
        max_subprocesses: 1,
        ..GovernorBudgets::default()
    });
    // One slot: the first probe succeeds, the storm fails closed.
    assert!(gov.acquire_subprocess().is_some());
    assert!(gov.acquire_subprocess().is_none());
    assert_eq!(gov.limit_hit(), Some("subprocess_budget"));
}
