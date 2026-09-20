//! P4 apply engine tests (disposable fixtures only; never the real HOME).

use configctl_core::apply::{apply_plan, ApplyOptions};
use configctl_core::command::{CommandOutput, FakeCommandRunner};
use configctl_core::observe::{FileObs, ObservedState};
use configctl_core::plan::{self, OperationKind};
use configctl_core::profile::{FileEntry, Profile};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn ok_out(stdout: &str) -> CommandOutput {
    CommandOutput {
        status: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    }
}

fn fail_out() -> CommandOutput {
    CommandOutput {
        status: Some(1),
        stdout: String::new(),
        stderr: "E: Unable to locate package".into(),
        truncated: false,
        timed_out: false,
    }
}

struct Fx {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    bundle: PathBuf,
    state: PathBuf,
}

fn make_bundle(bundle: &Path, files: &[(&str, &str)], extra_toml: &str) {
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    let mut file_tables = String::new();
    for (target, body) in files {
        let stem = target.trim_start_matches("~/").replace(['/', '.'], "_");
        let rel = format!("files/{stem}");
        std::fs::write(bundle.join(&rel), body).unwrap();
        file_tables.push_str(&format!(
            "\n[[files]]\ntarget = \"{target}\"\nsource = \"{rel}\"\n"
        ));
    }
    let toml = format!("schema_version = 1\nname = \"work\"\n{file_tables}{extra_toml}");
    std::fs::write(bundle.join("profile.toml"), toml).unwrap();
}

fn setup(files: &[(&str, &str)], extra_toml: &str) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let bundle = tmp.path().join("work");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&home).unwrap();
    make_bundle(&bundle, files, extra_toml);
    Fx {
        _tmp: tmp,
        home,
        bundle,
        state,
    }
}

fn loaded(fx: &Fx) -> configctl_core::profile_load::LoadedProfile {
    configctl_core::profile_load::load_profile_dir(&fx.bundle).expect("load bundle")
}

fn observed_missing(targets: &[&str]) -> ObservedState {
    let mut st = ObservedState::default();
    for t in targets {
        st.files.insert(
            (*t).into(),
            FileObs {
                exists: false,
                is_symlink: false,
                is_non_regular: false,
                content_hash: None,
                len: None,
            },
        );
    }
    st
}

fn plan_for(fx: &Fx, st: &ObservedState, plan_id: &str) -> configctl_core::plan::Plan {
    let l = loaded(fx);
    let owned =
        configctl_core::state::ownership_for_profile(&fx.state, &l.identity).unwrap_or_default();
    let p = plan::build_plan(&l, st, &owned, plan_id, 1000);
    configctl_core::state::save_plan(&fx.state, &p, &l.dir).unwrap();
    p
}

fn yes(_: &configctl_core::plan::Plan) -> bool {
    true
}

#[test]
fn file_create_then_noop_is_idempotent() {
    let fx = setup(&[("~/.gitconfig", "[user]\n\tname = T\n")], "");
    let runner = FakeCommandRunner::new();
    let st = observed_missing(&["~/.gitconfig"]);
    plan_for(&fx, &st, "p-create");
    let rep = apply_plan(
        &fx.state,
        "p-create",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("apply");
    assert_eq!(rep.executed.len(), 1);
    assert_eq!(
        std::fs::read_to_string(fx.home.join(".gitconfig")).unwrap(),
        "[user]\n\tname = T\n"
    );
    // Ownership recorded.
    let owned = configctl_core::state::ownership_for_profile(&fx.state, "work").unwrap();
    assert!(owned.contains(&("file".to_string(), "~/.gitconfig".to_string())));
    // Second plan over the same state is a noop; applying the same plan again
    // is refused (already applied), but a fresh plan converges.
    let st2 = {
        let mut s = ObservedState::default();
        let h = configctl_core::hash::file_content_hash(b"[user]\n\tname = T\n");
        s.files.insert(
            "~/.gitconfig".into(),
            FileObs {
                exists: true,
                is_symlink: false,
                is_non_regular: false,
                content_hash: Some(h),
                len: Some(10),
            },
        );
        s
    };
    let l = loaded(&fx);
    let owned2 = configctl_core::state::ownership_for_profile(&fx.state, "work").unwrap();
    let p2 = plan::build_plan(&l, &st2, &owned2, "p-noop", 1001);
    assert!(plan::is_noop(&p2));
}

#[test]
fn unmanaged_file_refused_without_adopt() {
    let fx = setup(&[("~/.gitconfig", "desired\n")], "");
    std::fs::write(fx.home.join(".gitconfig"), "foreign\n").unwrap();
    let runner = FakeCommandRunner::new();
    let mut st = ObservedState::default();
    st.files.insert(
        "~/.gitconfig".into(),
        FileObs {
            exists: true,
            is_symlink: false,
            is_non_regular: false,
            content_hash: Some(configctl_core::hash::file_content_hash(b"foreign\n")),
            len: Some(8),
        },
    );
    plan_for(&fx, &st, "p-conflict");
    let err = apply_plan(
        &fx.state,
        "p-conflict",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::Conflict(_)
    ));
    // Untouched.
    assert_eq!(
        std::fs::read_to_string(fx.home.join(".gitconfig")).unwrap(),
        "foreign\n"
    );
}

#[test]
fn adopt_backs_up_and_takes_ownership() {
    let fx = setup(&[("~/.gitconfig", "desired\n")], "");
    std::fs::write(fx.home.join(".gitconfig"), "foreign\n").unwrap();
    let runner = FakeCommandRunner::new();
    let mut st = ObservedState::default();
    st.files.insert(
        "~/.gitconfig".into(),
        FileObs {
            exists: true,
            is_symlink: false,
            is_non_regular: false,
            content_hash: Some(configctl_core::hash::file_content_hash(b"foreign\n")),
            len: Some(8),
        },
    );
    plan_for(&fx, &st, "p-adopt");
    let rep = apply_plan(
        &fx.state,
        "p-adopt",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            adopt: vec!["~/.gitconfig".into()],
            ..Default::default()
        },
        &yes,
    )
    .expect("adopt apply");
    assert_eq!(
        std::fs::read_to_string(fx.home.join(".gitconfig")).unwrap(),
        "desired\n"
    );
    // Backup holds the previous bytes.
    let sha = rep.executed[0].backup_sha.clone().expect("backup sha");
    let backed = configctl_core::backup::get(&fx.state, &sha).unwrap();
    assert_eq!(backed, b"foreign\n");
}

#[test]
fn toctou_guard_aborts_on_changed_file() {
    let fx = setup(&[("~/.gitconfig", "desired\n")], "");
    std::fs::write(fx.home.join(".gitconfig"), "v1\n").unwrap();
    let runner = FakeCommandRunner::new();
    // Plan while managed and matching v1.
    configctl_core::state::ensure_state_dir(&fx.state).unwrap();
    configctl_core::state::record_owned(
        &fx.state,
        "file",
        "~/.gitconfig",
        "work",
        Some(&configctl_core::hash::file_content_hash(b"v1\n")),
        1,
    )
    .unwrap();
    // Payload differs from v1 → FileUpdate with expected_before=v1 hash.
    let mut st = ObservedState::default();
    st.files.insert(
        "~/.gitconfig".into(),
        FileObs {
            exists: true,
            is_symlink: false,
            is_non_regular: false,
            content_hash: Some(configctl_core::hash::file_content_hash(b"v1\n")),
            len: Some(3),
        },
    );
    let plan = plan_for(&fx, &st, "p-toctou");
    assert!(plan
        .operations
        .iter()
        .any(|o| o.kind == OperationKind::FileUpdate));
    // Attacker/user changes the file after planning.
    std::fs::write(fx.home.join(".gitconfig"), "v2-evil\n").unwrap();
    let err = apply_plan(
        &fx.state,
        "p-toctou",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::Conflict(_)
    ));
    assert_eq!(
        std::fs::read_to_string(fx.home.join(".gitconfig")).unwrap(),
        "v2-evil\n"
    );
}

#[test]
fn fail_stop_leaves_later_ops_unexecuted() {
    // Two creates; the first succeeds, the second's parent is blocked by a
    // regular file (sorted order: ~/.aaa_ok first, ~/.zzz/deep second).
    let fx = setup(&[("~/.aaa_ok", "ok\n"), ("~/.zzz/deep", "x\n")], "");
    std::fs::write(fx.home.join(".zzz"), "blocker\n").unwrap();
    let runner = FakeCommandRunner::new();
    let st = observed_missing(&["~/.aaa_ok", "~/.zzz/deep"]);
    plan_for(&fx, &st, "p-failstop");
    let err = apply_plan(
        &fx.state,
        "p-failstop",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::OpFailed { .. }
    ));
    // First op applied, plan marked partial.
    assert!(fx.home.join(".aaa_ok").exists());
    let (_, status, _) = configctl_core::state::load_plan(&fx.state, "p-failstop").unwrap();
    assert_eq!(status, "partial");
    // Journal: op-0001 DONE, op-0002 FAILED, nothing after.
    let journal = configctl_core::state::journal_for_plan(&fx.state, "p-failstop").unwrap();
    assert!(journal
        .iter()
        .any(|e| e.op_id == "op-0001" && e.phase == "DONE"));
    assert!(journal
        .iter()
        .any(|e| e.op_id == "op-0002" && e.phase == "FAILED"));
}

#[test]
fn stale_profile_is_refused() {
    let fx = setup(&[("~/.gitconfig", "v1\n")], "");
    let runner = FakeCommandRunner::new();
    let st = observed_missing(&["~/.gitconfig"]);
    plan_for(&fx, &st, "p-stale");
    // Change the profile payload after planning (stem for `~/.gitconfig` is
    // `files/_gitconfig` per the test bundle layout).
    std::fs::write(fx.bundle.join("files/_gitconfig"), "v2\n").unwrap();
    let err = apply_plan(
        &fx.state,
        "p-stale",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::Conflict(_)
    ));
    assert!(!fx.home.join(".gitconfig").exists());
}

#[test]
fn never_replans_silently() {
    // Applying twice: second apply of the same id is refused (already applied),
    // never silently regenerated.
    let fx = setup(&[("~/.gitconfig", "v1\n")], "");
    let runner = FakeCommandRunner::new();
    let st = observed_missing(&["~/.gitconfig"]);
    plan_for(&fx, &st, "p-once");
    apply_plan(
        &fx.state,
        "p-once",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("first apply");
    let err = apply_plan(
        &fx.state,
        "p-once",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::Conflict(_)
    ));
}

#[test]
fn lock_contention_fails_closed() {
    let fx = setup(&[("~/.gitconfig", "v1\n")], "");
    let runner = FakeCommandRunner::new();
    let st = observed_missing(&["~/.gitconfig"]);
    plan_for(&fx, &st, "p-lock");
    let _held = configctl_core::lock::acquire(&fx.state).expect("hold lock");
    let err = apply_plan(
        &fx.state,
        "p-lock",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::Conflict(_)
    ));
}

#[test]
fn package_privilege_failure_is_honest() {
    let fx = setup(&[], "\n[packages]\napt = [\"ripgrep\"]\n");
    let runner = FakeCommandRunner::new();
    // precheck dpkg-query: not installed.
    runner.queue(ok_out("deinstall ok config-files\n"));
    // sudo apt-get: privilege failure.
    runner.queue(CommandOutput {
        status: Some(1),
        stdout: String::new(),
        stderr: "sudo: a password is required\n".into(),
        truncated: false,
        timed_out: false,
    });
    let st = ObservedState::default();
    plan_for(&fx, &st, "p-priv");
    let err = apply_plan(
        &fx.state,
        "p-priv",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(
        matches!(err, configctl_core::apply::ApplyError::Privilege(_)),
        "got {err:?}"
    );
}

#[test]
fn package_install_argv_is_fixed() {
    let fx = setup(&[], "\n[packages]\napt = [\"ripgrep\"]\n");
    let runner = FakeCommandRunner::new();
    runner.queue(ok_out("deinstall ok config-files\n"));
    runner.queue(ok_out("done\n"));
    runner.queue(ok_out("install ok installed\n")); // postcheck
    let st = ObservedState::default();
    plan_for(&fx, &st, "p-apt");
    apply_plan(
        &fx.state,
        "p-apt",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("apt apply");
    let calls = runner.recorded();
    let sudo = calls
        .iter()
        .find(|c| c.program.to_string_lossy() == "sudo")
        .expect("sudo call");
    assert_eq!(sudo.args, vec!["-n", "apt-get", "install", "-y", "ripgrep"]);
    let _ = fail_out;
}

#[test]
fn dry_run_writes_nothing() {
    let fx = setup(&[("~/.gitconfig", "v1\n")], "");
    let runner = FakeCommandRunner::new();
    let st = observed_missing(&["~/.gitconfig"]);
    plan_for(&fx, &st, "p-dry");
    let rep = apply_plan(
        &fx.state,
        "p-dry",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            dry_run: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("dry run");
    assert!(rep.dry_run);
    assert!(!fx.home.join(".gitconfig").exists());
    // No journal, status still planned.
    let journal = configctl_core::state::journal_for_plan(&fx.state, "p-dry").unwrap();
    assert!(journal.is_empty());
    let (_, status, _) = configctl_core::state::load_plan(&fx.state, "p-dry").unwrap();
    assert_eq!(status, "planned");
}

#[test]
fn env_literal_is_set_in_managed_file() {
    let fx = setup(&[], "\n[environment]\nEDITOR = \"nvim\"\n");
    let runner = FakeCommandRunner::new();
    let st = ObservedState::default();
    let plan = plan_for(&fx, &st, "p-env");
    assert!(plan
        .operations
        .iter()
        .any(|o| o.target == "EDITOR" && o.kind == OperationKind::EnvironmentSchemaChange));
    apply_plan(
        &fx.state,
        "p-env",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("env apply");
    let text =
        std::fs::read_to_string(fx.home.join(".config/environment.d/90-configctl.conf")).unwrap();
    assert!(text.contains("EDITOR=nvim"));
}

#[test]
fn journal_phases_are_complete_for_file_update() {
    let fx = setup(&[("~/.gitconfig", "desired\n")], "");
    std::fs::write(fx.home.join(".gitconfig"), "old\n").unwrap();
    configctl_core::state::ensure_state_dir(&fx.state).unwrap();
    configctl_core::state::record_owned(&fx.state, "file", "~/.gitconfig", "work", None, 1)
        .unwrap();
    let runner = FakeCommandRunner::new();
    let mut st = ObservedState::default();
    st.files.insert(
        "~/.gitconfig".into(),
        FileObs {
            exists: true,
            is_symlink: false,
            is_non_regular: false,
            content_hash: Some(configctl_core::hash::file_content_hash(b"old\n")),
            len: Some(4),
        },
    );
    plan_for(&fx, &st, "p-journal");
    apply_plan(
        &fx.state,
        "p-journal",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("apply");
    let journal = configctl_core::state::journal_for_plan(&fx.state, "p-journal").unwrap();
    let phases: Vec<&str> = journal.iter().map(|e| e.phase.as_str()).collect();
    for expected in [
        "INTENT",
        "PRECHECK",
        "BACKUP",
        "EXECUTE",
        "POSTCHECK",
        "DONE",
    ] {
        assert!(phases.contains(&expected), "missing {expected}: {phases:?}");
    }
}

#[test]
fn symlink_target_refused_at_apply() {
    let fx = setup(&[("~/.gitconfig", "desired\n")], "");
    std::fs::write(fx.home.join("real"), "x\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(fx.home.join("real"), fx.home.join(".gitconfig")).unwrap();
    let runner = FakeCommandRunner::new();
    // Plan observed it missing (attacker swapped after plan).
    let st = observed_missing(&["~/.gitconfig"]);
    plan_for(&fx, &st, "p-symlink");
    let err = apply_plan(
        &fx.state,
        "p-symlink",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        configctl_core::apply::ApplyError::Conflict(_)
    ));
    // Symlink untouched.
    assert!(std::fs::symlink_metadata(fx.home.join(".gitconfig"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn profile_toml_map_style_is_rejected() {
    // P2 stores files as `[[files]]`; the doc-style `[files."~/x"]` map must
    // not parse (fail closed, never half-applied).
    let tmp = tempfile::tempdir().unwrap();
    let bundle = tmp.path().join("b");
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/g"), "x\n").unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"b\"\n[files.\"~/.g\"]\nsource = \"files/g\"\n",
    )
    .unwrap();
    assert!(configctl_core::profile_load::load_profile_dir(&bundle).is_err());
}

fn _unused_profiles() {
    let _ = BTreeMap::<String, String>::new();
    let _ = BTreeSet::<String>::new();
    let _ = Profile::new("x");
    let _ = FileEntry {
        target: String::new(),
        source: String::new(),
        mode: None,
        origin: None,
        detected_by: None,
        classification: None,
    };
}
