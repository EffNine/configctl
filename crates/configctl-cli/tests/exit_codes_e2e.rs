//! Exit-code conformance (CLI_SPEC §1.1): every failure mode must emit the
//! documented code. Tests call command handlers directly (the repo's e2e
//! pattern — no shell-outs); the `exit_code` fields asserted here are the
//! exact values `main.rs` hands to the process exit.
//!
//! Conformance table (mode → emitted → documented):
//! | usage / bad profile / bad id            → 2 | §1.1 usage/config error    ✓ |
//! | verify drift/missing                    → 3 | §2.7 / §1.1                 ✓ |
//! | apply declined (no --yes, non-TTY)      → 4 | §4                         ✓ |
//! | stale plan / tampered plan / unknown id → 5 | §1.1 conflict/unsafe       ✓ |
//! | capture overwrite without --force       → 5 | §2.3 (fixed: was 2)        ✓ |
//! | onboard into non-empty dir w/o --force  → 5 | §2.16                      ✓ |
//! | rollback of never-applied/already-done  → 2 | §2.17 (exit 2/5)            ✓ |
//! | secret backend unavailable              → 6 | §1.1                        ✓ |
//! | secrets list with no backend            → 0 + backend_error statuses     ✓ |
//! | clean verify / apply / capture / list   → 0 | success                    ✓ |

use configctl_cli::commands::{apply as apply_cmd, plan as plan_cmd, secrets as secrets_cmd};
use configctl_core::command::FakeCommandRunner;

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn runner() -> FakeCommandRunner {
    FakeCommandRunner::new()
}

/// Minimal file bundle: one managed file target.
fn file_bundle(tmp: &std::path::Path, content: &[u8]) -> (PathBuf, PathBuf, PathBuf) {
    let home = tmp.join("home");
    let bundle = tmp.join("work");
    let state = tmp.join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/g"), content).unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[[files]]\ntarget = \"~/.g\"\nsource = \"files/g\"\n",
    )
    .unwrap();
    (home, bundle, state)
}

use std::path::PathBuf;

fn state_str(tmp: &std::path::Path) -> String {
    tmp.join("state").to_string_lossy().into_owned()
}

fn plan_apply(
    bundle: &std::path::Path,
    state: &std::path::Path,
    home: &std::path::Path,
    id: &str,
    runner: &FakeCommandRunner,
) -> apply_cmd::ApplyOutput {
    let planned = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(home),
        runner,
        Some(id),
        Some(1),
    );
    assert!(planned.error.is_none(), "{:?}", planned.error);
    apply_cmd::run_apply(
        Some(id),
        None,
        Some(state.to_str().unwrap()),
        Some(home),
        true,
        false,
        &[],
        false,
        runner,
    )
}

#[test]
fn usage_error_is_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    // apply takes a plan ID, never a profile path.
    let out = apply_cmd::run_apply(
        Some(tmp.path().to_str().unwrap()),
        None,
        Some(state_str(tmp.path())).as_deref(),
        Some(tmp.path()),
        true,
        false,
        &[],
        false,
        &runner(),
    );
    assert_eq!(out.exit_code, 2);
    // verify against a malformed bundle is also usage-class.
    let bad = tmp.path().join("bad");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("profile.toml"), "nope [[[\n").unwrap();
    let v = configctl_cli::commands::verify::run_verify(
        bad.to_str().unwrap(),
        Some(tmp.path()),
        false,
        &runner(),
    );
    assert_eq!(v.exit_code, 2);
    // env consolidate --mode move with neither preview flag refuses as usage.
    let (home, bundle, _state) = file_bundle(tmp.path(), b"v1\n");
    let m = configctl_cli::commands::env::run_env_consolidate_move(
        Some(bundle.to_str().unwrap()),
        Some(&home),
        false,
        None,
        None,
    );
    assert_eq!(m.exit_code, 2);
}

#[test]
fn verify_drift_is_exit_3() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, _state) = file_bundle(tmp.path(), b"desired\n");
    std::fs::write(home.join(".g"), "tampered\n").unwrap();
    let out = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &runner(),
    );
    assert_eq!(out.exit_code, 3);
}

#[test]
fn apply_declined_without_yes_is_exit_4() {
    // No TTY under cargo test: interactive approval is impossible, so a
    // non-approved apply must decline (exit 4), never hang.
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, state) = file_bundle(tmp.path(), b"v1\n");
    let planned = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner(),
        Some("decline-1"),
        Some(1),
    );
    assert!(planned.error.is_none());
    let out = apply_cmd::run_apply(
        Some("decline-1"),
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        false,
        false,
        &[],
        false,
        &runner(),
    );
    assert_eq!(out.exit_code, 4);
}

#[test]
fn stale_plan_apply_refusal_is_exit_5() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, state) = file_bundle(tmp.path(), b"v1\n");
    let planned = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner(),
        Some("stale-1"),
        Some(1),
    );
    assert!(planned.error.is_none());
    // Hand-edit the profile after planning: the plan is now stale.
    std::fs::write(bundle.join("files/g"), "v2\n").unwrap();
    let out = apply_cmd::run_apply(
        Some("stale-1"),
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        &[],
        false,
        &runner(),
    );
    assert_eq!(out.exit_code, 5);
    let msg = apply_cmd::error_message(out.error.as_ref().unwrap());
    assert!(
        msg.contains("changed since planning"),
        "stale refusal must say so: {msg}"
    );
}

#[test]
fn tampered_plan_load_is_exit_5() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, state) = file_bundle(tmp.path(), b"v1\n");
    let planned = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner(),
        Some("tamper-1"),
        Some(1),
    );
    assert!(planned.error.is_none());
    // Valid JSON, changed semantics: the recomputed hash must catch it.
    let doc = state.join("plans").join("tamper-1.json");
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&doc).unwrap()).unwrap();
    let ops = v["operations"].as_array().unwrap().len();
    assert!(ops > 0, "fixture must produce operations");
    v["operations"][0]["summary"] = serde_json::json!("TAMPERED BY TEST");
    std::fs::write(&doc, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let out = apply_cmd::run_apply(
        Some("tamper-1"),
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        &[],
        false,
        &runner(),
    );
    assert_eq!(out.exit_code, 5);
    // The same tampered document must also stop rollback (shared load path).
    let rb = configctl_cli::commands::rollback::run_rollback(
        Some("tamper-1"),
        None,
        false,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        false,
        &runner(),
    );
    assert_eq!(rb.exit_code, 5);
}

#[test]
fn unknown_plan_apply_is_exit_5() {
    let tmp = tempfile::tempdir().unwrap();
    let out = apply_cmd::run_apply(
        Some("no-such-plan"),
        None,
        Some(state_str(tmp.path())).as_deref(),
        Some(tmp.path()),
        true,
        false,
        &[],
        false,
        &runner(),
    );
    assert_eq!(out.exit_code, 5);
}

#[test]
fn secret_backend_unavailable_is_exit_6() {
    let _guard = ENV_LOCK.lock().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let old_path = std::env::var_os("PATH");
    let old_test_dir = std::env::var_os("CONFIGCTL_SECRET_TEST_DIR");
    std::env::remove_var("CONFIGCTL_SECRET_TEST_DIR");
    std::env::set_var("PATH", empty.path());
    let out = secrets_cmd::run_get("secret://a/b/C", false, false, false, &runner());
    // Restore before asserting so a failure cannot leak env into other tests.
    if let Some(p) = old_path {
        std::env::set_var("PATH", p);
    }
    if let Some(d) = old_test_dir {
        std::env::set_var("CONFIGCTL_SECRET_TEST_DIR", d);
    }
    assert_eq!(out.exit_code, 6);
    assert!(out.value.is_none());
}

#[test]
fn secrets_list_without_backend_degrades_honestly() {
    // Documented `list` contract: references + status, never values — with no
    // backend the statuses read `backend_error` and the exit stays 0.
    let _guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let old_path = std::env::var_os("PATH");
    let old_test_dir = std::env::var_os("CONFIGCTL_SECRET_TEST_DIR");
    let empty = tempfile::tempdir().unwrap();
    std::env::remove_var("CONFIGCTL_SECRET_TEST_DIR");
    std::env::set_var("PATH", empty.path());
    let bundle = tmp.path().join("prof");
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"prof\"\n",
    )
    .unwrap();
    std::fs::write(
        bundle.join("secrets.manifest.toml"),
        "schema_version = 1\n\n[[secrets]]\nname = \"KEY\"\nproject = \"api\"\nsource = \".env\"\nclassification = \"secret\"\nbackend = \"secret-service\"\nref = \"secret://work/api/KEY\"\nrequired = true\n",
    )
    .unwrap();
    let out = secrets_cmd::run_list(Some(bundle.to_str().unwrap()), None, &runner());
    if let Some(p) = old_path {
        std::env::set_var("PATH", p);
    }
    if let Some(d) = old_test_dir {
        std::env::set_var("CONFIGCTL_SECRET_TEST_DIR", d);
    }
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.entries.len(), 1);
    assert_eq!(out.entries[0].status, "backend_error");
}

#[test]
fn success_paths_are_exit_0() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, state) = file_bundle(tmp.path(), b"v1\n");
    let r = runner();
    // plan persists (no error, no conflicts → the CLI maps this to exit 0).
    let planned = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &r,
        Some("ok-1"),
        Some(1),
    );
    assert!(planned.error.is_none());
    assert!(planned.plan.as_ref().unwrap().conflicts.is_empty());
    // apply executes cleanly.
    let applied = plan_apply(&bundle, &state, &home, "ok-1-apply", &r);
    assert_eq!(applied.exit_code, 0);
    // verify matches after apply.
    let v = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &r,
    );
    assert_eq!(v.exit_code, 0);
    // rollback --list succeeds.
    let rb = configctl_cli::commands::rollback::run_rollback(
        None,
        None,
        true,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        false,
        &r,
    );
    assert_eq!(rb.exit_code, 0);
}

#[test]
fn capture_overwrite_refusal_is_exit_5() {
    let tmp = tempfile::tempdir().unwrap();
    let from = tmp.path().join("proj");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::write(from.join("x.txt"), "x\n").unwrap();
    let out_dir = tmp.path().join("bundle");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("existing.txt"), "mine\n").unwrap();
    let out = configctl_cli::commands::capture::run_capture(
        None,
        &[from.to_string_lossy().into_owned()],
        &[],
        Some(out_dir.to_str().unwrap()),
        false,
        None,
        false,
        None,
        &runner(),
    );
    assert!(out.error_envelope.is_some());
    assert_eq!(out.exit_code, 5);
    // Untouched: the refusal wrote nothing.
    assert!(!out_dir.join("profile.toml").exists());
    // --force proceeds past the refusal.
    let forced = configctl_cli::commands::capture::run_capture(
        None,
        &[from.to_string_lossy().into_owned()],
        &[],
        Some(out_dir.to_str().unwrap()),
        true,
        None,
        false,
        None,
        &runner(),
    );
    assert!(forced.error_envelope.is_none());
    assert_eq!(forced.exit_code, 0);
}

#[test]
fn onboard_into_non_empty_dir_is_exit_5() {
    let tmp = tempfile::tempdir().unwrap();
    let existing = tmp.path().join("existing");
    std::fs::create_dir_all(&existing).unwrap();
    std::fs::write(existing.join("keep.txt"), "mine\n").unwrap();
    let out = configctl_cli::commands::onboard::run_onboard(
        &[],
        &[],
        Some(existing.to_str().unwrap()),
        Some(tmp.path()),
        false,
        &runner(),
    );
    assert_eq!(out.exit_code, 5);
    assert!(out.error.is_some());
}

#[test]
fn rollback_of_never_applied_plan_is_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, state) = file_bundle(tmp.path(), b"v1\n");
    let planned = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner(),
        Some("never-1"),
        Some(1),
    );
    assert!(planned.error.is_none());
    // Planned but never applied: nothing to roll back (usage-class).
    let rb = configctl_cli::commands::rollback::run_rollback(
        Some("never-1"),
        None,
        false,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        false,
        &runner(),
    );
    assert_eq!(rb.exit_code, 2);
}

#[test]
fn status_with_unloadable_profile_is_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let out = configctl_cli::commands::status::run_status(
        Some(tmp.path().join("nope").to_str().unwrap()),
        Some(state_str(tmp.path())).as_deref(),
        Some(tmp.path()),
        &runner(),
    );
    assert_eq!(out.exit_code, 2);
}

#[test]
fn why_outside_home_is_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let out = configctl_cli::commands::why::run_why(
        "/etc/passwd",
        Some(state_str(tmp.path())).as_deref(),
        Some(tmp.path()),
    );
    assert_eq!(out.exit_code, 2);
}

#[test]
fn init_refusal_without_force_is_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = tmp.path().join("config.toml");
    let first = configctl_cli::commands::init::run_init(
        None,
        false,
        Some(cfg.to_str().unwrap()),
        Some(tmp.path().join("state").to_str().unwrap()),
    );
    assert_eq!(first.exit_code, 0);
    let second = configctl_cli::commands::init::run_init(
        None,
        false,
        Some(cfg.to_str().unwrap()),
        Some(tmp.path().join("state2").to_str().unwrap()),
    );
    assert_eq!(second.exit_code, 2);
}
