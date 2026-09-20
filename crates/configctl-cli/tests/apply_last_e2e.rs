//! `--last` plan resolution for apply and rollback.

use configctl_core::command::FakeCommandRunner;

fn world() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let bundle = tmp.path().join("work");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/g"), "payload\n").unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[[files]]\ntarget = \"~/.g\"\nsource = \"files/g\"\n",
    )
    .unwrap();
    (tmp, home, bundle, state)
}

#[test]
fn apply_last_resolves_the_newest_plan() {
    let (_tmp, home, bundle, state) = world();
    let runner = FakeCommandRunner::new();
    for (id, created) in [("last-1", 1000i64), ("last-2", 2000i64)] {
        let planned = configctl_cli::commands::plan::run_plan(
            bundle.to_str().unwrap(),
            Some(state.to_str().unwrap()),
            Some(&home),
            &runner,
            Some(id),
            Some(created),
        );
        assert!(planned.error.is_none(), "plan {id} failed");
    }

    let id = configctl_cli::commands::apply::resolve_last_plan(&state).expect("latest plan");
    assert_eq!(id, "last-2");

    // The resolved id is directly applyable (dry-run, non-interactive).
    let out = configctl_cli::commands::apply::run_apply(
        Some(&id),
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        true,
        &[],
        false,
        &runner,
    );
    assert!(out.report.is_some(), "apply --last dry-run should preview");
    assert_eq!(out.exit_code, 0);
}

#[test]
fn last_without_any_plans_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");

    match configctl_cli::commands::apply::resolve_last_plan(&state) {
        Err(configctl_core::apply::ApplyError::Usage(msg)) => {
            assert!(msg.contains("no plans"), "{msg:?}");
        }
        other => panic!("expected apply Usage error, got {other:?}"),
    }
    match configctl_cli::commands::rollback::resolve_last_plan(&state) {
        Err(configctl_core::rollback::RollbackError::Usage(msg)) => {
            assert!(msg.contains("no plans"), "{msg:?}");
        }
        other => panic!("expected rollback Usage error, got {other:?}"),
    }
}
