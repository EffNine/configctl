//! P3 `configctl plan` end-to-end tests (disposable fixtures only).

use configctl_cli::commands::plan as plan_cmd;
use configctl_core::command::{CommandOutput, FakeCommandRunner};

fn ok_out(stdout: &str) -> CommandOutput {
    CommandOutput {
        status: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    }
}

/// A fake home + profile bundle: one managed file payload, one package, one
/// literal env var, one service.
fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bundle = tmp.path().join("work");
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/gitconfig"), "[user]\n\tname = Test\n").unwrap();
    // NOTE: the typed Profile model uses `[[files]]` / `[[services]]` arrays.
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[packages]\napt = [\"ripgrep\"]\n\n[[files]]\ntarget = \"~/.gitconfig\"\nsource = \"files/gitconfig\"\n\n[environment]\nEDITOR = \"nvim\"\n\n[[services]]\nname = \"docker.service\"\nenabled = true\n",
    )
    .unwrap();
    (tmp, home, bundle)
}

fn runner_no_packages() -> FakeCommandRunner {
    let r = FakeCommandRunner::new();
    // dpkg-query: ripgrep missing.
    r.queue(ok_out("jq\t1.7\tamd64\n"));
    // systemctl --user list-units: manager available.
    r.queue(ok_out("docker.service loaded active running\n"));
    // is-enabled / is-active for docker.service.
    r.queue(ok_out("disabled\n"));
    r.queue(ok_out("inactive\n"));
    r
}

#[test]
fn plan_creates_and_persists() {
    let (_tmp, home, bundle) = fixture();
    let state = _tmp.path().join("state");
    let runner = runner_no_packages();
    let out = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("plan-001"),
        Some(1000),
    );
    assert!(
        out.error.is_none(),
        "error: {:?}",
        out.error.map(|e| e.message)
    );
    let plan = out.plan.unwrap();
    assert_eq!(plan.plan_id, "plan-001");
    assert!(!plan.plan_hash.is_empty());
    assert!(plan.operations.iter().any(|o| o.target == "ripgrep"));
    assert!(plan.operations.iter().any(|o| o.target == "~/.gitconfig"));
    // Persisted + reloadable.
    let (reloaded, _, _) =
        configctl_core::state::load_plan(&state, "plan-001").expect("reload plan");
    assert_eq!(reloaded.plan_hash, plan.plan_hash);
    // Human rendering mentions the plan id and no secret values.
    let human = plan_cmd::render_human(&plan);
    assert!(human.contains("plan-001"));
    // JSON parses.
    let v: serde_json::Value =
        serde_json::from_str(&plan_cmd::plan_json(&plan).to_string()).unwrap();
    assert!(v.get("plan_hash").is_some());
}

#[test]
fn plan_is_deterministic() {
    let (_tmp, home, bundle) = fixture();
    let state = _tmp.path().join("state");
    let out1 = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner_no_packages(),
        Some("plan-a"),
        Some(1000),
    );
    let out2 = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner_no_packages(),
        Some("plan-b"),
        Some(9999),
    );
    assert_eq!(out1.plan.unwrap().plan_hash, out2.plan.unwrap().plan_hash);
}

#[test]
fn unmanaged_existing_file_is_conflict() {
    let (_tmp, home, bundle) = fixture();
    // Pre-create an unmanaged file at the target.
    std::fs::write(home.join(".gitconfig"), "foreign content\n").unwrap();
    let state = _tmp.path().join("state");
    let runner = runner_no_packages();
    let out = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("plan-c"),
        Some(1000),
    );
    let plan = out.plan.expect("plan");
    assert!(plan.conflicts.iter().any(|c| c.code == "unmanaged_exists"));
}

#[test]
fn managed_file_becomes_update_not_conflict() {
    let (_tmp, home, bundle) = fixture();
    std::fs::write(home.join(".gitconfig"), "foreign content\n").unwrap();
    let state = _tmp.path().join("state");
    // Take ownership first (simulates a prior approved apply).
    configctl_core::state::ensure_state_dir(&state).unwrap();
    configctl_core::state::record_owned(&state, "file", "~/.gitconfig", "work", None, 1).unwrap();
    let runner = runner_no_packages();
    let out = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("plan-d"),
        Some(1000),
    );
    let plan = out.plan.expect("plan");
    assert!(plan
        .operations
        .iter()
        .any(|o| o.target == "~/.gitconfig" && format!("{:?}", o.kind) == "FileUpdate"));
    assert!(!plan.conflicts.iter().any(|c| c.target == "~/.gitconfig"));
}

#[test]
fn malformed_profile_is_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("bad");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("profile.toml"), "this is not [[valid\n").unwrap();
    let runner = FakeCommandRunner::new();
    let out = plan_cmd::run_plan(
        bad.to_str().unwrap(),
        Some(tmp.path().join("state").to_str().unwrap()),
        Some(tmp.path()),
        &runner,
        None,
        None,
    );
    assert!(out.plan.is_none());
    assert!(out.error.is_some());
}

#[test]
fn plan_never_writes_to_home() {
    let (_tmp, home, bundle) = fixture();
    let before: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let state = _tmp.path().join("state");
    let _ = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner_no_packages(),
        Some("plan-e"),
        Some(1000),
    );
    let after: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(before, after, "plan must not mutate the machine");
}

#[test]
fn native_managers_plan_and_render_per_manager() {
    // Composition: a profile declaring dnf/pacman packages plans
    // provider-tagged ops and renders them under per-manager groups. On this
    // (non-native) host both managers are Unavailable — recorded honestly as
    // Unsupported, never silently skipped.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let bundle = tmp.path().join("work");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[packages]\ndnf = [\"htop\"]\npacman = [\"jq\"]\n",
    )
    .unwrap();
    let runner = FakeCommandRunner::new();
    let out = plan_cmd::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("plan-native"),
        Some(1000),
    );
    assert!(out.error.is_none());
    let plan = out.plan.expect("plan");
    let dnf_op = plan
        .operations
        .iter()
        .find(|o| o.provider == "dnf")
        .expect("dnf op");
    let pacman_op = plan
        .operations
        .iter()
        .find(|o| o.provider == "pacman")
        .expect("pacman op");
    // Provider tags are always present (static registration). The Unsupported
    // expectation below only holds off the native distro — on a Fedora/Arch
    // host the same ops would be installs, so gate on the live platform.
    let live = configctl_core::package_managers::read_os_release();
    let native = |family| {
        live.as_ref()
            .map(|os| configctl_core::package_managers::family_matches(os, family))
            .unwrap_or(false)
    };
    use configctl_core::package_managers::NativeFamily;
    if !native(NativeFamily::Fedora) {
        assert_eq!(format!("{:?}", dnf_op.kind), "Unsupported");
    }
    if !native(NativeFamily::Arch) {
        assert_eq!(format!("{:?}", pacman_op.kind), "Unsupported");
    }
    let human = plan_cmd::render_human(&plan);
    assert!(human.contains("Packages (dnf):"), "{human:?}");
    assert!(human.contains("Packages (pacman):"), "{human:?}");
    if !native(NativeFamily::Fedora) {
        assert!(human.contains("package htop: package manager unavailable"));
    }
}
