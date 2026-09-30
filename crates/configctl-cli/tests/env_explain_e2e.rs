//! `env explain` + `env consolidate` end-to-end over a temp home.
//!
//! `explain` and `--dry-run` are strictly read-only. `consolidate` persists a
//! plan and writes nothing; the plan is applied through the normal journaled
//! `apply` path and undone through `rollback`.

use configctl_cli::commands::env::{run_env_consolidate, run_env_explain};
use configctl_core::command::FakeCommandRunner;
use std::path::Path;

const SECRET_VALUE: &str = "ghp_zzzzzzzzzzzzzzzzzzzz";

/// A home with shell startup files, plus a profile bundle that declares two
/// environment literals.
fn world(tmp: &Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let home = tmp.join("home");
    let bundle = tmp.join("work");
    let state = tmp.join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(
        home.join(".bashrc"),
        format!("export EDITOR=nano\nexport GITHUB_TOKEN={SECRET_VALUE}\n"),
    )
    .unwrap();
    std::fs::write(home.join(".profile"), "export EDITOR=emacs\n").unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[environment]\nEDITOR = \"vim\"\nLANG = \"en_US.UTF-8\"\n",
    )
    .unwrap();
    (home, bundle, state)
}

#[test]
fn explain_reports_sources_conflicts_and_never_leaks_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join(".bashrc"),
        format!(
            "export EDITOR=nano\n\
             export PATH=\"$PATH:$HOME/.local/bin\"\n\
             export GITHUB_TOKEN={SECRET_VALUE}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        home.join(".profile"),
        "export EDITOR=emacs\nexport LANG=en_US.UTF-8\n",
    )
    .unwrap();
    let envd = home.join(".config/environment.d");
    std::fs::create_dir_all(&envd).unwrap();
    std::fs::write(envd.join("90-configctl.conf"), "EDITOR=code\n").unwrap();

    let out = run_env_explain(Some(&home));
    assert!(out.error.is_none());
    assert_eq!(out.exit_code, 0);

    assert!(out.text.contains("~/.bashrc"));
    assert!(out.text.contains("left alone"));
    assert!(out.text.contains("GITHUB_TOKEN"));

    // The secret value must never appear anywhere in the output.
    assert!(!out.text.contains(SECRET_VALUE));
    assert!(!out.data.to_string().contains(SECRET_VALUE));

    let conflicts = out.data["conflicts"].as_array().unwrap();
    assert!(conflicts.iter().any(|c| c["name"] == "EDITOR"));

    let prec = out.data["precedence"].as_array().unwrap();
    assert!(prec
        .iter()
        .any(|p| p["name"] == "LANG" && p["value"] == "en_US.UTF-8"));
}

#[test]
fn consolidate_dry_run_previews_without_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, _state) = world(tmp.path());

    let out = run_env_consolidate(
        Some(bundle.to_str().unwrap()),
        None,
        Some(&home),
        true,
        "include",
    );
    assert!(out.error.is_none(), "unexpected error: {:?}", out.error);
    assert_eq!(out.exit_code, 0);
    assert!(out.text.contains("Dry run"));
    assert!(out.data["dry_run"] == true);

    // Canonical content comes from the profile and is sorted.
    let canonical = out.data["canonical_content"].as_str().unwrap();
    assert!(canonical.contains("EDITOR=vim"));
    assert!(canonical.contains("LANG=en_US.UTF-8"));
    let e = canonical.find("EDITOR=").unwrap();
    let l = canonical.find("LANG=").unwrap();
    assert!(e < l);

    // Nothing was written, and no plan was persisted.
    assert!(!home.join(".config/configctl/env.sh").exists());
    assert!(
        !home.join(".bashrc").is_file() || {
            let b = std::fs::read_to_string(home.join(".bashrc")).unwrap();
            !b.contains(">>> configctl env >>>")
        }
    );
}

#[test]
fn consolidate_plan_applies_and_rolls_back_byte_exact() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, state) = world(tmp.path());
    let state_s = state.to_str().unwrap().to_string();

    let bashrc_before = std::fs::read_to_string(home.join(".bashrc")).unwrap();

    let planned = run_env_consolidate(
        Some(bundle.to_str().unwrap()),
        Some(&state_s),
        Some(&home),
        false,
        "include",
    );
    assert!(planned.error.is_none(), "{:?}", planned.error);
    let plan_id = planned.data["plan_id"].as_str().unwrap().to_string();
    assert!(planned.data["operations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|o| o["kind"] == "EnvFileWrite"));
    assert!(planned.data["operations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|o| o["kind"] == "IncludeLineAdd"));

    // Planning must not touch the machine.
    assert!(!home.join(".config/configctl/env.sh").exists());
    assert_eq!(
        std::fs::read_to_string(home.join(".bashrc")).unwrap(),
        bashrc_before
    );

    // Apply through the normal journaled path.
    let runner = FakeCommandRunner::new();
    let applied = configctl_cli::commands::apply::run_apply(
        Some(&plan_id),
        None,
        Some(&state_s),
        Some(&home),
        true,
        false,
        &[],
        false,
        &runner,
    );
    assert!(
        applied.error.is_none(),
        "apply failed: {:?}",
        applied.error.map(|e| format!("{e:?}"))
    );

    let canonical = std::fs::read_to_string(home.join(".config/configctl/env.sh")).unwrap();
    assert!(canonical.contains("EDITOR=vim"));
    assert!(canonical.contains("LANG=en_US.UTF-8"));
    // The secret value is never written to the canonical shell file.
    assert!(!canonical.contains(SECRET_VALUE));

    let bashrc_after = std::fs::read_to_string(home.join(".bashrc")).unwrap();
    assert!(bashrc_after.starts_with(&bashrc_before));
    assert!(bashrc_after.contains(">>> configctl env >>>"));
    assert!(bashrc_after.contains("<<< configctl env <<<"));

    // Both env artifacts are in sync with the profile, so verify is clean.
    let verified = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &runner,
    );
    assert!(verified.error.is_none(), "{:?}", verified.error);
    assert_eq!(verified.exit_code, 0, "verify should be clean after apply");

    // Rolling back restores both files byte-exact.
    let rolled = configctl_cli::commands::rollback::run_rollback(
        None,
        Some(&plan_id),
        false,
        Some(&state_s),
        Some(&home),
        true,
        false,
        false,
        &runner,
    );
    assert!(
        rolled.error.is_none(),
        "rollback failed: {:?}",
        rolled.error.map(|e| format!("{e:?}"))
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".bashrc")).unwrap(),
        bashrc_before
    );
    assert!(!home.join(".config/configctl/env.sh").exists());
    let envd = std::fs::read_to_string(home.join(".config/environment.d/90-configctl.conf"))
        .unwrap_or_default();
    assert!(!envd.contains("EDITOR=vim"));
}

#[test]
fn consolidate_is_idempotent_and_refuses_stale_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, state) = world(tmp.path());
    let state_s = state.to_str().unwrap().to_string();
    let runner = FakeCommandRunner::new();

    // First pass: plan + apply.
    let plan1 = run_env_consolidate(
        Some(bundle.to_str().unwrap()),
        Some(&state_s),
        Some(&home),
        false,
        "include",
    );
    let id1 = plan1.data["plan_id"].as_str().unwrap().to_string();
    let _ = configctl_cli::commands::apply::run_apply(
        Some(&id1),
        None,
        Some(&state_s),
        Some(&home),
        true,
        false,
        &[],
        false,
        &runner,
    );

    // Second pass: everything already holds the desired state -> NoOp plan.
    let plan2 = run_env_consolidate(
        Some(bundle.to_str().unwrap()),
        Some(&state_s),
        Some(&home),
        false,
        "include",
    );
    assert!(plan2.error.is_none(), "{:?}", plan2.error);
    let ops = plan2.data["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["kind"], "NoOp");

    // A plan built for one content must refuse when the file changed under it.
    // Restore the pre-apply state so a fresh plan has work to do.
    let bashrc = std::fs::read_to_string(home.join(".bashrc")).unwrap();
    let reverted: String = bashrc
        .lines()
        .take_while(|l| !l.contains(">>> configctl env >>>"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(home.join(".bashrc"), format!("{reverted}\n")).unwrap();

    let plan3 = run_env_consolidate(
        Some(bundle.to_str().unwrap()),
        Some(&state_s),
        Some(&home),
        false,
        "include",
    );
    let id3 = plan3.data["plan_id"].as_str().unwrap().to_string();

    // Change the file between planning and applying.
    let hand_edited = format!("{reverted}\n# hand-added line\n");
    std::fs::write(home.join(".bashrc"), &hand_edited).unwrap();

    let applied3 = configctl_cli::commands::apply::run_apply(
        Some(&id3),
        None,
        Some(&state_s),
        Some(&home),
        true,
        false,
        &[],
        false,
        &runner,
    );
    // The stale plan must refuse rather than overwrite the user's edit.
    assert!(
        applied3.error.is_some(),
        "a stale plan must be refused, got: {:?}",
        applied3.error
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".bashrc")).unwrap(),
        hand_edited
    );
    assert!(!hand_edited.contains(">>> configctl env >>>"));
}
