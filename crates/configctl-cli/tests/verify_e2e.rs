//! P5 verify tests: deterministic drift fixtures, exit codes, read-only.

use configctl_cli::commands::verify as verify_cmd;
use configctl_core::command::{CommandOutput, FakeCommandRunner};
use configctl_core::verify::CheckStatus;

fn ok_out(stdout: &str) -> CommandOutput {
    CommandOutput {
        status: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    }
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let bundle = tmp.path().join("work");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/g"), "desired\n").unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[packages]\napt = [\"ripgrep\", \"jq\"]\n\n[[files]]\ntarget = \"~/.g\"\nsource = \"files/g\"\n\n[environment]\nEDITOR = \"nvim\"\n",
    )
    .unwrap();
    (tmp, home, bundle)
}

/// Runner where: ripgrep installed, jq missing, git user set, no systemd.
fn drifted_runner() -> FakeCommandRunner {
    let r = FakeCommandRunner::new();
    // dpkg-query full list: ripgrep only.
    r.queue(ok_out("ripgrep\t14.0\tamd64\n"));
    // git config --global --list.
    r.queue(ok_out("user.name=Test\nuser.email=t@e.com\n"));
    r
}

#[test]
fn detects_drift_missing_and_match() {
    let (_tmp, home, bundle) = fixture();
    // File matches; env literal missing (no managed env file yet).
    std::fs::write(home.join(".g"), "desired\n").unwrap();
    let out = verify_cmd::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &drifted_runner(),
    );
    assert!(out.error.is_none());
    let rep = out.report.unwrap();
    let status = |resource: &str, target: &str| {
        rep.results
            .iter()
            .find(|r| r.resource == resource && r.target == target)
            .map(|r| r.status)
    };
    assert_eq!(status("package", "ripgrep"), Some(CheckStatus::Match));
    assert_eq!(status("package", "jq"), Some(CheckStatus::Missing));
    assert_eq!(status("file", "~/.g"), Some(CheckStatus::Match));
    assert_eq!(status("env", "EDITOR"), Some(CheckStatus::Missing));
    assert_eq!(out.exit_code, 3);
}

#[test]
fn drifted_file_reports_drift() {
    let (_tmp, home, bundle) = fixture();
    std::fs::write(home.join(".g"), "tampered\n").unwrap();
    let out = verify_cmd::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &drifted_runner(),
    );
    let rep = out.report.unwrap();
    let f = rep.results.iter().find(|r| r.target == "~/.g").unwrap();
    assert_eq!(f.status, CheckStatus::Drift);
    assert_eq!(out.exit_code, 3);
}

#[test]
fn clean_tree_exits_zero() {
    let (_tmp, home, bundle) = fixture();
    std::fs::write(home.join(".g"), "desired\n").unwrap();
    std::fs::create_dir_all(home.join(".config/environment.d")).unwrap();
    std::fs::write(
        home.join(".config/environment.d/90-configctl.conf"),
        "EDITOR=nvim\n",
    )
    .unwrap();
    // Runner with both packages installed.
    let r = FakeCommandRunner::new();
    r.queue(ok_out("ripgrep\t14.0\tamd64\njq\t1.7\tamd64\n"));
    r.queue(ok_out("user.name=Test\n"));
    let out = verify_cmd::run_verify(bundle.to_str().unwrap(), Some(&home), false, &r);
    let rep = out.report.unwrap();
    assert!(
        rep.results.iter().all(|x| x.status == CheckStatus::Match),
        "{:?}",
        rep.results
            .iter()
            .map(|x| (&x.target, x.status))
            .collect::<Vec<_>>()
    );
    assert_eq!(out.exit_code, 0);
}

#[test]
fn unsupported_when_providers_gone() {
    let (_tmp, home, bundle) = fixture();
    let r = FakeCommandRunner::new();
    // dpkg-query fails; git missing.
    r.queue(CommandOutput {
        status: Some(1),
        ..Default::default()
    });
    r.queue(CommandOutput {
        status: Some(1),
        ..Default::default()
    });
    let out = verify_cmd::run_verify(bundle.to_str().unwrap(), Some(&home), false, &r);
    let rep = out.report.unwrap();
    assert!(rep
        .results
        .iter()
        .any(|x| x.status == CheckStatus::Unsupported));
}

#[test]
fn verify_never_repairs() {
    let (_tmp, home, bundle) = fixture();
    std::fs::write(home.join(".g"), "tampered\n").unwrap();
    let before = std::fs::read(home.join(".g")).unwrap();
    let out = verify_cmd::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &drifted_runner(),
    );
    assert_eq!(out.exit_code, 3);
    assert_eq!(std::fs::read(home.join(".g")).unwrap(), before);
    // No state dir created by verify.
    assert!(!_tmp.path().join(".local").exists());
}

#[test]
fn verify_json_parses_and_has_no_values() {
    let (_tmp, home, bundle) = fixture();
    std::fs::write(home.join(".g"), "desired\n").unwrap();
    let out = verify_cmd::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &drifted_runner(),
    );
    let rep = out.report.unwrap();
    let v = serde_json::to_value(rep).unwrap();
    let s = serde_json::to_string(&v).unwrap();
    let _: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert!(!s.contains("tampered"));
}

#[test]
fn malformed_profile_is_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("bad");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("profile.toml"), "nope [[[\n").unwrap();
    let out = verify_cmd::run_verify(
        bad.to_str().unwrap(),
        Some(tmp.path()),
        false,
        &FakeCommandRunner::new(),
    );
    assert_eq!(out.exit_code, 2);
    assert!(out.report.is_none());
}

#[test]
fn apply_then_verify_is_match() {
    // Idempotencyówki: apply → verify MATCH.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let bundle = tmp.path().join("work");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/g"), "v1\n").unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[[files]]\ntarget = \"~/.g\"\nsource = \"files/g\"\n",
    )
    .unwrap();
    let runner = FakeCommandRunner::new();
    let planned = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("v-1"),
        Some(1),
    );
    assert!(planned.error.is_none());
    let applied = configctl_cli::commands::apply::run_apply(
        Some("v-1"),
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        &[],
        false,
        &runner,
    );
    assert_eq!(applied.exit_code, 0);
    let out = verify_cmd::run_verify(bundle.to_str().unwrap(), Some(&home), false, &runner);
    assert_eq!(out.exit_code, 0, "{:?}", out.report.map(|r| r.results));
}
