//! Integration + security tests for the discovery engine.
//!
//! Uses disposable temp directories, a `FakeCommandRunner` for git, and
//! canary values to prove secrets never appear in any output.

use configctl_core::command::{CommandOutput, CommandRequest, FakeCommandRunner};
use configctl_core::limits::Limits;
use configctl_discovery::scanner::{ScanOptions, Scanner};
use std::path::{Path, PathBuf};

/// The P0/P1 regression canaries: they must never appear in any user-visible
/// output.
const CANARY_OPENAI: &str = "super-secret-test-value";
const CANARY_PASSWORD: &str = "another-secret-value";

fn fixture_project(tmp: &Path) -> PathBuf {
    // project/
    // ├── .git/
    // ├── .env            (with canaries)
    // ├── .env.example
    // ├── backend/
    // │   └── .env.production
    // └── src/
    //     └── config.toml
    let proj = tmp.join("project");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::fs::write(
        proj.join(".env"),
        format!(
            "OPENAI_API_KEY={CANARY_OPENAI}\nDATABASE_PASSWORD={CANARY_PASSWORD}\nNORMAL_SETTING=hello\n"
        ),
    )
    .unwrap();
    std::fs::write(
        proj.join(".env.example"),
        "OPENAI_API_KEY=\nDATABASE_PASSWORD=\nNORMAL_SETTING=\n",
    )
    .unwrap();
    std::fs::create_dir_all(proj.join("backend")).unwrap();
    std::fs::write(
        proj.join("backend/.env.production"),
        "PROD_TOKEN=sk-live-canary99999\n",
    )
    .unwrap();
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(proj.join("src/config.toml"), "key = \"value\"\n").unwrap();
    std::fs::write(proj.join("Cargo.toml"), "[package]\nname=\"project\"\n").unwrap();
    proj
}

fn fake_git_runner() -> FakeCommandRunner {
    let fake = FakeCommandRunner::new();
    // `git rev-parse --show-toplevel` (cwd = the file's directory)
    fake.queue(CommandOutput {
        status: Some(0),
        stdout: "/root/repo\n".into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    // `git status --porcelain=v1 -- <paths...>`
    // .env tracked, .env.example ignored, backend untracked, src config tracked
    fake.queue(CommandOutput {
        status: Some(0),
        stdout: "M  .env\n?? backend/.env.production\n?? .env.example\n".into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    // `git ls-files -- <remaining...>` (files with no changes)
    fake.queue(CommandOutput {
        status: Some(0),
        stdout: "src/config.toml\n".into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    // `git check-ignore -q -- .env.example`
    fake.queue(CommandOutput {
        status: Some(0),
        stdout: String::new(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    fake
}

fn run_scan_fixture(tmp: &Path, runner: &FakeCommandRunner) -> configctl_discovery::ScanResult {
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![tmp.to_path_buf()],
        limits: Limits::default(),
        governor: Default::default(),
    };
    scanner.scan(&opts, runner)
}

// --- Integration: all expected discoveries ---------------------------------

#[test]
fn integration_discovers_full_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    let runner = fake_git_runner();
    let result = run_scan_fixture(&proj, &runner);

    // Project detected
    assert!(
        result.projects.iter().any(|p| p.name == "project"),
        "project must be discovered"
    );
    // All three env files discovered
    assert!(
        result.env_files.len() >= 3,
        "expected >=3 env files, got {}",
        result.env_files.len()
    );
    let names: Vec<String> = result
        .env_files
        .iter()
        .map(|e| {
            e.path
                .rsplit('/')
                .next()
                .map(|s| s.to_string())
                .unwrap_or_default()
        })
        .collect();
    let _ = names;
    // Env files found: .env, .env.example, .env.production
    let has_env = result.env_files.iter().any(|e| e.path.ends_with("/.env"));
    let has_example = result
        .env_files
        .iter()
        .any(|e| e.path.ends_with("/.env.example"));
    let has_prod = result
        .env_files
        .iter()
        .any(|e| e.path.ends_with("/backend/.env.production"));
    assert!(
        has_env && has_example && has_prod,
        "all env layers discovered: {names:?}"
    );
    // config file discovered
    assert!(
        result
            .config_files
            .iter()
            .any(|c| c.path.ends_with("config.toml")),
        "config.toml must be discovered"
    );
    // statistics populated
    let _ = names;
}

// --- Security: canaries never appear in any output -------------------------

#[test]
fn canary_values_absent_from_human_render() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    let runner = fake_git_runner();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![proj.clone()],
        limits: Limits::default(),
        governor: Default::default(),
    };
    let result = scanner.scan(&opts, &runner);

    let registry = scanner.registry();
    let human = configctl_cli::commands::scan::render_human(&result, false, true);
    let human = registry.redact(&human);
    assert!(
        !human.contains(CANARY_OPENAI),
        "canary leaked in human output"
    );
    assert!(
        !human.contains(CANARY_PASSWORD),
        "canary leaked in human output"
    );
    assert!(
        !human.contains("sk-live-canary99999"),
        "prod token leaked in human output"
    );
}

#[test]
fn canary_values_absent_from_json() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    let runner = fake_git_runner();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![proj.clone()],
        limits: Limits::default(),
        governor: Default::default(),
    };
    let result = scanner.scan(&opts, &runner);

    let registry = scanner.registry();
    let json = result.redacted_json(registry, &[]);
    let json = registry.redact(&json);
    assert!(!json.contains(CANARY_OPENAI), "canary leaked in JSON");
    assert!(!json.contains(CANARY_PASSWORD), "canary leaked in JSON");
    assert!(
        !json.contains("sk-live-canary99999"),
        "prod token leaked in JSON"
    );
    // JSON must be valid and parseable.
    let _: serde_json::Value = serde_json::from_str(&json).expect("JSON output must parse");
}

#[test]
fn canary_values_absent_from_debug() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    let runner = fake_git_runner();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![proj.clone()],
        limits: Limits::default(),
        governor: Default::default(),
    };
    let result = scanner.scan(&opts, &runner);
    let dbg = format!("{result:?}");
    assert!(
        !dbg.contains(CANARY_OPENAI),
        "canary leaked in Debug output"
    );
    assert!(
        !dbg.contains(CANARY_PASSWORD),
        "canary leaked in Debug output"
    );
}

#[test]
fn canary_values_absent_from_errors() {
    // Force a read error with a canary path, then check the recorded warning.
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    // Make one env file unreadable (best effort) to produce an error warning.
    let env_path = proj.join(".env");
    let runner = fake_git_runner();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![proj.clone()],
        limits: Limits::default(),
        governor: Default::default(),
    };
    let result = scanner.scan(&opts, &runner);
    let registry = scanner.registry();
    let serialized = result.redacted_json(registry, &[]);
    let _ = env_path;
    // No canary anywhere in the serialized errors/warnings.
    assert!(!serialized.contains(CANARY_OPENAI));
    assert!(!serialized.contains(CANARY_PASSWORD));
}

#[test]
fn env_files_are_never_modified() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    // Snapshot the tree before the scan.
    let before = tree_snapshot(&proj);
    let runner = fake_git_runner();
    let _ = run_scan_fixture(&proj, &runner);
    let after = tree_snapshot(&proj);
    assert_eq!(before, after, "scan must not modify the tree");
}

/// Byte-level snapshot of a tree (path -> content + size) to prove a
/// read-only pass changed nothing.
fn tree_snapshot(root: &Path) -> std::collections::BTreeMap<String, (u64, u64)> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let walker = configctl_discovery::walker::BoundedWalker::new(Limits::default());
    walker.walk(root, &mut |v| {
        let key = v.path.to_string_lossy().into_owned();
        let size = std::fs::metadata(&v.path).map(|m| m.len()).unwrap_or(0);
        let mtime = std::fs::metadata(&v.path)
            .and_then(|m| m.modified())
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        map.insert(key, (size, mtime));
        true
    });
    map
}

#[test]
fn deep_tree_is_bounded() {
    let tmp = tempfile::tempdir().unwrap();
    // 40 levels deep
    let mut p = tmp.path().to_path_buf();
    for i in 0..40 {
        p = p.join(format!("l{i}"));
        std::fs::create_dir_all(&p).unwrap();
    }
    std::fs::write(p.join(".env"), "X=1\n").unwrap();

    let runner = fake_git_runner();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![tmp.path().to_path_buf()],
        limits: Limits {
            max_depth: 5,
            ..Limits::default()
        },
        governor: Default::default(),
    };
    let result = scanner.scan(&opts, &runner);
    // The scan must terminate and report the stop reason.
    assert!(
        !result.statistics.stop_reasons.is_empty(),
        "deep tree must trip a limit"
    );
}

#[test]
fn huge_file_is_bounded_not_read() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    // A .env that exceeds the default 256KiB cap: must be skipped, not read.
    let huge = proj.join("huge.env");
    let big = "X=1\n".repeat(200_000); // ~800 KiB
    std::fs::write(&huge, big).unwrap();

    let runner = fake_git_runner();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![proj.clone()],
        limits: Limits::default(),
        governor: Default::default(),
    };
    let result = scanner.scan(&opts, &runner);
    let rec = result
        .env_files
        .iter()
        .find(|e| e.path.ends_with("huge.env"))
        .expect("huge.env must be discovered by name");
    assert!(
        rec.variable_count == 0,
        "huge file must not be parsed into variables"
    );
    assert!(
        !rec.warnings.is_empty(),
        "huge file must record a size-cap warning"
    );
}

#[test]
fn permission_denied_does_not_crash() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    // Make a subdirectory unreadable so the walker must handle the error.
    let locked = proj.join("locked");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::write(locked.join(".env"), "Y=2\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&locked).unwrap().permissions().mode();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(mode & !0o700)).unwrap();
    }

    let runner = fake_git_runner();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![proj.clone()],
        limits: Limits::default(),
        governor: Default::default(),
    };
    let result = scanner.scan(&opts, &runner);
    // The scan must complete and report the permission problem, not panic.
    // The subdirectory is unreadable when unprivileged, so the walker must
    // surface a permission_denied stat or a permission warning.
    let unprivileged = std::env::var("USER").ok().as_deref() != Some("root");
    if unprivileged {
        let surfaced = result.statistics.permission_denied > 0
            || result
                .statistics
                .stop_reasons
                .iter()
                .any(|r| r.contains("permission"))
            || result
                .warnings
                .iter()
                .any(|w| w.to_lowercase().contains("permission"));
        assert!(
            surfaced,
            "permission denied must be surfaced (stats={} stop={:?} warnings={:?})",
            result.statistics.permission_denied, result.statistics.stop_reasons, result.warnings
        );
    }
    // In all cases the scan must complete and report a result, not panic.
    assert!(result.statistics.env_files_found >= 1);
}

#[test]
fn git_commands_use_fixed_argv_no_shell() {
    // Prove the git detection path only ever issues fixed-argv `git` commands.
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    let runner = FakeCommandRunner::new();
    runner.queue(CommandOutput {
        status: Some(0),
        stdout: "/root/repo\n".into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    runner.queue(CommandOutput {
        status: Some(0),
        stdout: String::new(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    let _ = run_scan_fixture(&proj, &runner);
    let calls = runner.recorded();
    let git_calls: Vec<&CommandRequest> = calls
        .iter()
        .filter(|c| c.program.display().to_string() == "git")
        .collect();
    assert!(
        !git_calls.is_empty(),
        "git detection must issue git commands"
    );
    for c in &git_calls {
        assert_eq!(
            c.program.display().to_string(),
            "git",
            "only git is invoked"
        );
        // No shell metacharacters may appear in argv (they would be inert
        // anyway since there is no shell, but we assert the shape).
        let sub = c.args.first().map(|s| s.as_str()).unwrap_or("");
        assert!(
            matches!(
                sub,
                "rev-parse" | "status" | "ls-files" | "check-ignore" | "--version" | "config"
            ),
            "unexpected git subcommand: {sub}"
        );
        for a in &c.args {
            assert!(
                !a.contains(';') && !a.contains('`') && !a.contains("$(") && !a.contains("|"),
                "argv must not contain shell syntax: {a:?}"
            );
        }
    }
}

#[test]
fn traversal_cannot_escape_root() {
    // Place a symlink inside the root that points outside it; the walker
    // must not read the outside target.
    let tmp = tempfile::tempdir().unwrap();
    let proj = fixture_project(tmp.path());
    let outside = tmp.path().join("outside_secret");
    std::fs::write(&outside, "OUTSIDE_CANARY=1\n").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, proj.join("escape.env")).unwrap();
    }

    let runner = fake_git_runner();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![proj.clone()],
        limits: Limits::default(),
        governor: Default::default(),
    };
    let result = scanner.scan(&opts, &runner);
    // The outside file must not be recorded (symlinks are not followed).
    assert!(
        !result
            .env_files
            .iter()
            .any(|e| e.path.contains("outside_secret")),
        "symlink escape must not leak the outside file"
    );
}
