//! `status` + `why` end-to-end over a real state store and a temp home.

use configctl_core::command::FakeCommandRunner;
use std::path::PathBuf;

fn world() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
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
fn status_and_why_reflect_a_real_apply() {
    let (_tmp, home, bundle, state) = world();
    let runner = FakeCommandRunner::new();
    let planned = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("st-1"),
        Some(2000),
    );
    assert!(planned.error.is_none(), "plan failed");
    let applied = configctl_cli::commands::apply::run_apply(
        Some("st-1"),
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        &[],
        false,
        &runner,
    );
    assert_eq!(applied.exit_code, 0, "apply failed");

    // status without a profile: state overview.
    let st = configctl_cli::commands::status::run_status(
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
    );
    assert!(st.error.is_none());
    assert!(st.text.contains("Plans"), "{}", st.text);
    assert!(st.text.contains("1 total"), "{}", st.text);
    assert_eq!(st.data["newest_plan"]["id"], "st-1");
    assert_eq!(st.data["newest_plan"]["status"], "applied");

    // status with a profile: drift counts.
    let st2 = configctl_cli::commands::status::run_status(
        Some(bundle.to_str().unwrap()),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
    );
    assert!(st2.error.is_none(), "{:?}", st2.error);
    assert!(st2.text.contains("MATCH"), "{}", st2.text);
    assert_eq!(st2.data["profile"]["summary"]["match_count"], 1);
    assert_eq!(st2.data["profile"]["summary"]["drift"], 0);

    // why: managed file with a last operation.
    let w =
        configctl_cli::commands::why::run_why("~/.g", Some(state.to_str().unwrap()), Some(&home));
    assert!(w.error.is_none(), "{:?}", w.error);
    assert_eq!(w.data["managed_by"], "work");
    assert_eq!(w.data["exists"], true);
    assert!(w.text.contains("last operation"), "{}", w.text);
    assert!(w.data["last_operation"]["plan_id"] == "st-1");

    // why: unmanaged and absent.
    let w2 = configctl_cli::commands::why::run_why(
        "~/.nope",
        Some(state.to_str().unwrap()),
        Some(&home),
    );
    assert!(w2.text.contains("nothing"), "{}", w2.text);
    assert_eq!(w2.data["exists"], false);
    assert!(w2.data["managed_by"].is_null());

    // why: targets outside $HOME are refused.
    let w3 = configctl_cli::commands::why::run_why("relative/path", None, Some(&home));
    assert_eq!(w3.exit_code, 2);
    assert!(w3.error.unwrap().contains("under $HOME"));
}

#[test]
fn status_without_state_is_informational() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("state");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let runner = FakeCommandRunner::new();
    let st = configctl_cli::commands::status::run_status(
        None,
        Some(missing.to_str().unwrap()),
        Some(&home),
        &runner,
    );
    assert!(st.error.is_none());
    assert!(st.text.contains("not initialized"), "{}", st.text);
    assert_eq!(st.data["state_initialized"], false);
    assert_eq!(st.exit_code, 0);
}
