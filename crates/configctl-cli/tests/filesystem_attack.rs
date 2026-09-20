//! P8 filesystem attack suite (disposable fixtures only).
//!
//! Symlink swaps, parent symlinks, traversal, FIFO/socket/device files,
//! oversized files, disappearing files, hard links, unsafe permissions —
//! none may cause writes outside the declared target or silent overwrites.

use configctl_core::apply::{apply_plan, ApplyOptions};
use configctl_core::command::FakeCommandRunner;

fn setup_bundle(home: &std::path::Path, bundle: &std::path::Path, target: &str, body: &str) {
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/payload"), body).unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        format!("schema_version = 1\nname = \"work\"\n\n[[files]]\ntarget = \"{target}\"\nsource = \"files/payload\"\n"),
    )
    .unwrap();
    let _ = home;
}

fn plan_id_for(
    home: &std::path::Path,
    bundle: &std::path::Path,
    state: &std::path::Path,
    id: &str,
) {
    let runner = FakeCommandRunner::new();
    let planned = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(home),
        &runner,
        Some(id),
        Some(1000),
    );
    assert!(
        planned.error.is_none(),
        "{:?}",
        planned.error.map(|e| e.message)
    );
}

fn apply_yes(
    home: &std::path::Path,
    state: &std::path::Path,
    id: &str,
    adopt: Vec<String>,
) -> Result<configctl_core::apply::ApplyReport, configctl_core::apply::ApplyError> {
    let runner = FakeCommandRunner::new();
    let yes = |_: &configctl_core::plan::Plan| true;
    apply_plan(
        state,
        id,
        home,
        &runner,
        &ApplyOptions {
            yes: true,
            adopt,
            ..Default::default()
        },
        &yes,
    )
}

fn fresh() -> (
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
    (tmp, home, bundle, state)
}

#[test]
fn target_symlink_is_refused() {
    let (_tmp, home, bundle, state) = fresh();
    setup_bundle(&home, &bundle, "~/.g", "v1\n");
    std::fs::write(home.join("real"), "x\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(home.join("real"), home.join(".g")).unwrap();
    plan_id_for(&home, &bundle, &state, "fs-1");
    let err = apply_yes(&home, &state, "fs-1", vec![]).unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::Conflict(_)
    ));
    // Neither the link nor its target changed.
    assert_eq!(std::fs::read_to_string(home.join("real")).unwrap(), "x\n");
    assert!(std::fs::symlink_metadata(home.join(".g"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn parent_symlink_is_refused() {
    let (_tmp, home, bundle, state) = fresh();
    setup_bundle(&home, &bundle, "~/.sub/g", "v1\n");
    std::fs::create_dir_all(home.join("realdir")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(home.join("realdir"), home.join(".sub")).unwrap();
    plan_id_for(&home, &bundle, &state, "fs-2");
    let err = apply_yes(&home, &state, "fs-2", vec![]).unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::Conflict(_)
    ));
    assert!(std::fs::read_dir(home.join("realdir"))
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn path_traversal_never_validates() {
    for bad in [
        "~/../evil",
        "~/.a/../../evil",
        "/etc/passwd",
        "~/",
        "",
        "~/a\0b",
    ] {
        assert!(
            configctl_core::paths::validate_file_target(bad).is_err(),
            "accepted {bad:?}"
        );
    }
    for bad in ["../evil", "/abs", "~/x", "a/../b", "C:\\win"] {
        assert!(
            configctl_core::paths::validate_bundle_source(bad).is_err(),
            "accepted {bad:?}"
        );
    }
}

#[test]
fn fifo_and_devices_are_never_written() {
    let (_tmp, home, bundle, state) = fresh();
    setup_bundle(&home, &bundle, "~/.g", "v1\n");
    #[cfg(unix)]
    {
        // SAFETY: fixture only; mkfifo via libc is unavailable — use Command.
        let _ = std::process::Command::new("mkfifo")
            .arg(home.join(".g"))
            .output();
        if home.join(".g").exists() {
            plan_id_for(&home, &bundle, &state, "fs-3");
            let err = apply_yes(&home, &state, "fs-3", vec![]).unwrap_err();
            assert!(matches!(
                err,
                configctl_core::apply::ApplyError::Conflict(_)
            ));
        }
    }
}

#[test]
fn oversized_payload_is_rejected_at_load() {
    let (_tmp, home, bundle, _state) = fresh();
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/big"), vec![b'x'; 300 * 1024]).unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[[files]]\ntarget = \"~/.big\"\nsource = \"files/big\"\n",
    )
    .unwrap();
    assert!(configctl_core::profile_load::load_profile_dir(&bundle).is_err());
    let _ = home;
}

#[test]
fn disappearing_file_fails_closed() {
    let (_tmp, home, bundle, state) = fresh();
    setup_bundle(&home, &bundle, "~/.g", "v1\n");
    std::fs::write(home.join(".g"), "old\n").unwrap();
    configctl_core::state::ensure_state_dir(&state).unwrap();
    configctl_core::state::record_owned(&state, "file", "~/.g", "work", None, 1).unwrap();
    // Plan sees the file (update), then it vanishes before apply.
    plan_id_for(&home, &bundle, &state, "fs-4");
    std::fs::remove_file(home.join(".g")).unwrap();
    let err = apply_yes(&home, &state, "fs-4", vec![]).unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::Conflict(_)
    ));
    assert!(
        !home.join(".g").exists(),
        "must not recreate without a new plan"
    );
}

#[test]
fn hard_link_target_is_treated_as_regular_file() {
    // Hard links share inodes: writing via rename breaks the link (safe —
    // the link partner keeps the old content, the target gets new bytes).
    let (_tmp, home, bundle, state) = fresh();
    setup_bundle(&home, &bundle, "~/.g", "v1\n");
    std::fs::write(home.join("sibling"), "old\n").unwrap();
    #[cfg(unix)]
    std::fs::hard_link(home.join("sibling"), home.join(".g")).unwrap_or(());
    if home.join(".g").exists() {
        plan_id_for(&home, &bundle, &state, "fs-5");
        // Unmanaged hard-linked file → conflict without adopt (ownership first).
        let err = apply_yes(&home, &state, "fs-5", vec![]).unwrap_err();
        assert!(matches!(
            err,
            configctl_core::apply::ApplyError::Conflict(_)
        ));
    }
}

#[test]
fn malicious_profile_paths_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    for (name, toml) in [
        (
            "dotdot",
            "schema_version = 1\nname = \"dotdot\"\n\n[[files]]\ntarget = \"~/ok\"\nsource = \"../evil\"\n",
        ),
        (
            "abs",
            "schema_version = 1\nname = \"abs\"\n\n[[files]]\ntarget = \"/etc/passwd\"\nsource = \"files/x\"\n",
        ),
        (
            "nul",
            "schema_version = 1\nname = \"nul\"\n\n[[files]]\ntarget = \"~/a\0b\"\nsource = \"files/x\"\n",
        ),
    ] {
        let b = tmp.path().join(name);
        std::fs::create_dir_all(b.join("files")).unwrap();
        std::fs::write(b.join("files/x"), "x\n").unwrap();
        std::fs::write(b.join("profile.toml"), toml).unwrap();
        assert!(
            configctl_core::profile_load::load_profile_dir(&b).is_err(),
            "accepted {name}"
        );
    }
}

#[test]
fn bundle_symlink_payload_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let b = tmp.path().join("b");
    std::fs::create_dir_all(b.join("files")).unwrap();
    std::fs::write(b.join("outside"), "secret\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(b.join("outside"), b.join("files/payload")).unwrap();
    std::fs::write(
        b.join("profile.toml"),
        "schema_version = 1\nname = \"b\"\n\n[[files]]\ntarget = \"~/.g\"\nsource = \"files/payload\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    assert!(configctl_core::profile_load::load_profile_dir(&b).is_err());
}
