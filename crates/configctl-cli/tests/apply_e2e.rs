//! P4 `configctl apply` CLI contract tests (no real mutation).

use configctl_cli::commands::apply as apply_cmd;
use configctl_core::command::FakeCommandRunner;

#[test]
fn apply_rejects_profile_path() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle = tmp.path().join("work");
    std::fs::create_dir_all(&bundle).unwrap();
    let runner = FakeCommandRunner::new();
    let out = apply_cmd::run_apply(
        Some(bundle.to_str().unwrap()),
        None,
        Some(tmp.path().join("state").to_str().unwrap()),
        Some(tmp.path()),
        true,
        false,
        &[],
        false,
        &runner,
    );
    assert_eq!(out.exit_code, 2);
    assert!(out.report.is_none());
}

#[test]
fn apply_requires_a_plan_id() {
    let tmp = tempfile::tempdir().unwrap();
    let runner = FakeCommandRunner::new();
    let out = apply_cmd::run_apply(
        None,
        None,
        Some(tmp.path().join("state").to_str().unwrap()),
        Some(tmp.path()),
        true,
        false,
        &[],
        false,
        &runner,
    );
    assert_eq!(out.exit_code, 2);
}

#[test]
fn apply_json_requires_yes() {
    let tmp = tempfile::tempdir().unwrap();
    let runner = FakeCommandRunner::new();
    let out = apply_cmd::run_apply(
        Some("plan-123"),
        None,
        Some(tmp.path().join("state").to_str().unwrap()),
        Some(tmp.path()),
        false,
        false,
        &[],
        true,
        &runner,
    );
    assert_eq!(out.exit_code, 2);
}

#[test]
fn apply_unknown_plan_is_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let runner = FakeCommandRunner::new();
    let out = apply_cmd::run_apply(
        Some("no-such-plan"),
        None,
        Some(tmp.path().join("state").to_str().unwrap()),
        Some(tmp.path()),
        true,
        false,
        &[],
        false,
        &runner,
    );
    assert_eq!(out.exit_code, 5);
    assert!(out.report.is_none());
}

#[test]
fn apply_full_lifecycle_json_parses() {
    // plan → approve+apply → JSON report parses.
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
        Some("lc-1"),
        Some(1000),
    );
    assert!(planned.error.is_none());
    let out = apply_cmd::run_apply(
        Some("lc-1"),
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        &[],
        true,
        &runner,
    );
    assert_eq!(
        out.exit_code,
        0,
        "{:?}",
        out.error.map(|e| apply_cmd::error_message(&e))
    );
    let rep = out.report.unwrap();
    let v: serde_json::Value =
        serde_json::from_str(&apply_cmd::report_json(&rep).to_string()).unwrap();
    assert_eq!(v.get("plan_id").and_then(|x| x.as_str()), Some("lc-1"));
    assert_eq!(std::fs::read_to_string(home.join(".g")).unwrap(), "v1\n");
}
