//! Temp-HOME lifecycle consistency (v1.3 polish, item 2).
//!
//! The whole lifecycle must work when one `--home <DIR>` (plus
//! `--state-dir`) is threaded through every command — no `HOME` env
//! override, no hand-kept consistency. This test never touches the `HOME`
//! env var: every call takes the home/state explicitly, exactly as the CLI
//! flags supply them. Sequence (must pass in this order):
//! consolidate include → apply → verify → move --dry-run → move
//! --emit-patch → rollback byte-exact.

use configctl_cli::commands::env::{run_env_consolidate, run_env_consolidate_move};
use configctl_core::command::FakeCommandRunner;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Messy temp home + profile bundle (same shape as the move-mode world):
/// managed matches, a mismatched duplicate, PATH/special, a conditional.
fn world(tmp: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let home = tmp.join("home");
    let bundle = tmp.join("work");
    let state = tmp.join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bundle).unwrap();
    let block = configctl_core::envmap::include_block();
    std::fs::write(
        home.join(".bashrc"),
        "export EDITOR=vim\n\
         export LANG=en_US.UTF-8\n\
         export PATH=\"$PATH:$HOME/.local/bin\"\n\
         if [ -n \"$FOO\" ]; then\n\
           export NESTED=yes\n\
         fi\n",
    )
    .unwrap();
    std::fs::write(home.join(".zshrc"), format!("export EDITOR=vim\n\n{block}")).unwrap();
    std::fs::write(
        home.join(".profile"),
        "export LANG=en_US.UTF-8\nexport EDITOR=emacs\n",
    )
    .unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[environment]\nEDITOR = \"vim\"\nLANG = \"en_US.UTF-8\"\n",
    )
    .unwrap();
    (home, bundle, state)
}

fn snapshot(home: &Path) -> BTreeMap<String, Vec<u8>> {
    [".bashrc", ".zshrc", ".profile"]
        .iter()
        .map(|r| (r.to_string(), std::fs::read(home.join(r)).unwrap()))
        .collect()
}

#[test]
fn temp_home_full_lifecycle_with_explicit_home_and_state_dir() {
    // NOTE: no HOME env override anywhere in this test. `home`/`state`
    // stand in for `--home <DIR>` / `--state-dir <DIR>` on every command.
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, state) = world(tmp.path());
    let state_s = state.to_str().unwrap().to_string();
    let bundle_s = bundle.to_str().unwrap().to_string();
    let runner = FakeCommandRunner::new();
    let pristine = snapshot(&home);

    // 1. consolidate include → journaled plan (explicit --home + --state-dir).
    let planned = run_env_consolidate(
        Some(&bundle_s),
        Some(&state_s),
        Some(&home),
        false,
        "include",
    );
    assert!(planned.error.is_none(), "{:?}", planned.error);
    let plan_id = planned.data["plan_id"].as_str().unwrap().to_string();

    // 2. apply with the same home/state (the old bug: plain `apply --last`
    //    re-resolved the real $HOME and tripped the stale-plan guard).
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
        "{:?}",
        applied.error.map(|e| format!("{e:?}"))
    );

    // 3. verify with the same home.
    let verified =
        configctl_cli::commands::verify::run_verify(&bundle_s, Some(&home), false, &runner);
    assert_eq!(
        verified.exit_code, 0,
        "verify must be clean after include apply"
    );

    // 4. move --dry-run with the same home: eligible list, strictly read-only.
    let before_move = snapshot(&home);
    let preview = run_env_consolidate_move(Some(&bundle_s), Some(&home), true, None, None);
    assert!(preview.error.is_none(), "{:?}", preview.error);
    assert_eq!(preview.exit_code, 0);
    assert!(
        !preview.data["eligible"].as_array().unwrap().is_empty(),
        "expected eligible tombstones"
    );
    assert_eq!(snapshot(&home), before_move, "dry run must not mutate");

    // 5. move --emit-patch with the same home: patch + backups, no mutation.
    let patch_path = tmp.path().join("move.patch");
    let emitted =
        run_env_consolidate_move(Some(&bundle_s), Some(&home), false, Some(&patch_path), None);
    assert!(emitted.error.is_none(), "{:?}", emitted.error);
    assert_eq!(emitted.exit_code, 0);
    assert!(patch_path.is_file());
    assert_eq!(
        snapshot(&home),
        before_move,
        "emit must not mutate rc files"
    );
    let dry = std::process::Command::new("patch")
        .args(["--dry-run", "-p0", "--silent"])
        .current_dir(&home)
        .stdin(std::fs::File::open(&patch_path).unwrap())
        .status()
        .expect("patch binary must exist");
    assert!(dry.success(), "emitted patch must apply with patch -p0");

    // 6. rollback with the same home/state: byte-exact restore of the
    //    pre-apply rc files.
    let rb = configctl_cli::commands::rollback::run_rollback(
        Some(&plan_id),
        None,
        false,
        Some(&state_s),
        Some(&home),
        true,
        false,
        false,
        &runner,
    );
    assert_eq!(rb.exit_code, 0, "{:?}", rb.error.map(|e| format!("{e:?}")));
    assert_eq!(
        snapshot(&home),
        pristine,
        "rollback must restore the pre-apply rc files byte-exact"
    );
}
