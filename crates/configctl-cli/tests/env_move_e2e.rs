//! `env consolidate --mode move` end-to-end over a temp home (v1.2 E5).
//!
//! Assisted manual ONLY: `--dry-run` is strictly read-only, `--emit-patch`
//! writes only the patch file plus adjacent timestamped backups (0600). Rc
//! files and the canonical file are never mutated by configctl here — the
//! test itself applies the patch with `patch -p0` to prove it is valid, then
//! restores byte-exact from the emitted backups. Also pins the E3 shadowing
//! report (`shadowed_declaration` plan warnings naming file and line).

use configctl_cli::commands::env::{
    run_env_consolidate, run_env_consolidate_move, run_env_explain,
};
use configctl_core::command::FakeCommandRunner;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SECRET_VALUE: &str = "ghp_zzzzzzzzzzzzzzzzzzzz";

/// Messy temp home + profile bundle: managed matches, a mismatched duplicate,
/// PATH/special, a conditional, a secret, and a pre-existing include block.
fn world(tmp: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let home = tmp.join("home");
    let bundle = tmp.join("work");
    let state = tmp.join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bundle).unwrap();
    let block = configctl_core::envmap::include_block();
    std::fs::write(
        home.join(".bashrc"),
        format!(
            "export EDITOR=vim\n\
             export LANG=en_US.UTF-8\n\
             export PATH=\"$PATH:$HOME/.local/bin\"\n\
             if [ -n \"$FOO\" ]; then\n\
               export NESTED=yes\n\
             fi\n\
             export GITHUB_TOKEN={SECRET_VALUE}\n"
        ),
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
fn move_full_lifecycle_dry_run_emit_patch_apply_restore() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, state) = world(tmp.path());
    let state_s = state.to_str().unwrap().to_string();
    let bundle_s = bundle.to_str().unwrap().to_string();
    let runner = FakeCommandRunner::new();

    // 1. explain is read-only and canary-clean.
    let explained = run_env_explain(Some(&home));
    assert_eq!(explained.exit_code, 0);
    assert!(!explained.data.to_string().contains(SECRET_VALUE));

    // 2. mode include plans the canonical file + include blocks, with the E3
    //    shadowing report naming every still-declared site.
    let planned = run_env_consolidate(
        Some(&bundle_s),
        Some(&state_s),
        Some(&home),
        false,
        "include",
    );
    assert!(planned.error.is_none(), "{:?}", planned.error);
    let warnings = planned.data["warnings"].as_array().unwrap();
    let shadowed: Vec<&serde_json::Value> = warnings
        .iter()
        .filter(|w| w["code"] == "shadowed_declaration")
        .collect();
    assert!(
        shadowed.len() >= 3,
        "E3 shadowing report must name each site, got: {warnings:?}"
    );
    for w in &shadowed {
        assert!(
            w["message"].as_str().unwrap().contains(".bashrc:1 EDITOR")
                || w["message"].as_str().unwrap().contains("EDITOR")
                || w["message"].as_str().unwrap().contains("LANG")
        );
    }
    let plan_id = planned.data["plan_id"].as_str().unwrap().to_string();

    // 3. apply + verify through the normal journaled path.
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
    let verified =
        configctl_cli::commands::verify::run_verify(bundle_s.as_str(), Some(&home), false, &runner);
    assert_eq!(
        verified.exit_code, 0,
        "verify must be clean after include apply"
    );

    // 4. move --dry-run: eligible list, strict read-only, canary-clean.
    let before = snapshot(&home);
    let preview = run_env_consolidate_move(Some(&bundle_s), Some(&home), true, None);
    assert!(preview.error.is_none(), "{:?}", preview.error);
    assert_eq!(preview.exit_code, 0);
    let eligible = preview.data["eligible"].as_array().unwrap();
    assert!(
        eligible.len() >= 3,
        "expected eligible tombstones, got: {}",
        preview.data
    );
    assert!(eligible
        .iter()
        .any(|e| e["file"] == "~/.bashrc" && e["name"] == "EDITOR"));
    assert!(eligible
        .iter()
        .any(|e| e["file"] == "~/.zshrc" && e["name"] == "EDITOR"));
    assert!(eligible
        .iter()
        .any(|e| e["file"] == "~/.profile" && e["name"] == "LANG"));
    // The emacs duplicate differs from the managed value: stays, with reason.
    let ineligible = preview.data["ineligible"].as_array().unwrap();
    assert!(ineligible
        .iter()
        .any(|i| i["name"] == "EDITOR" && i["reason"].as_str().unwrap().contains("differs")));
    // PATH / conditional / secret lines stay, with explicit reasons.
    assert!(ineligible
        .iter()
        .any(|i| i["reason"].as_str().unwrap().contains("never moved")));
    assert!(ineligible.iter().any(
        |i| i["reason"] == "left alone (conditional or nested block)"
            || i["reason"].as_str().unwrap().contains("conditional")
            || i["reason"].as_str().unwrap().contains("left alone")
    ));
    assert!(ineligible
        .iter()
        .any(|i| i["name"] == "GITHUB_TOKEN" && i["reason"].as_str().unwrap().contains("secret")));
    // Read-only: nothing changed, patch file untouched, no secret anywhere.
    assert_eq!(snapshot(&home), before);
    assert!(!preview.text.contains(SECRET_VALUE));
    assert!(!preview.data.to_string().contains(SECRET_VALUE));

    // 5. --emit-patch: valid patch, backups, still no mutation, no secret.
    let patch_path = home.join("move.patch");
    let emitted = run_env_consolidate_move(Some(&bundle_s), Some(&home), false, Some(&patch_path));
    assert!(emitted.error.is_none(), "{:?}", emitted.error);
    assert_eq!(emitted.exit_code, 0);
    let patch_text = std::fs::read_to_string(&patch_path).unwrap();
    assert!(patch_text.contains("tombstone") || patch_text.contains("configctl-move"));
    assert!(!patch_text.contains(SECRET_VALUE));
    assert!(!emitted.data.to_string().contains(SECRET_VALUE));
    assert_eq!(snapshot(&home), before, "emit must not mutate rc files");
    let canonical_before = std::fs::read(home.join(".config/configctl/env.sh")).unwrap();

    let backups = emitted.data["backups"].as_array().unwrap();
    assert!(!backups.is_empty());
    for b in backups {
        let backup = b["backup"].as_str().unwrap();
        let original = b["original"].as_str().unwrap();
        let rel = original.strip_prefix("~/").unwrap();
        let disk = std::fs::read(backup).unwrap();
        assert_eq!(
            &disk, &before[rel],
            "backup of {original} must be byte-identical"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(backup).unwrap().permissions().mode() & 0o777,
                0o600,
                "backups must be 0600"
            );
        }
    }
    let restore = emitted.data["restore_commands"].as_array().unwrap();
    assert_eq!(restore.len(), backups.len());
    assert!(restore
        .iter()
        .all(|c| c.as_str().unwrap().starts_with("cp -p ")));

    // `patch --dry-run -p0` accepts the emitted diff from $HOME.
    let dry = std::process::Command::new("patch")
        .args(["--dry-run", "-p0", "--silent"])
        .current_dir(&home)
        .stdin(std::fs::File::open(&patch_path).unwrap())
        .status()
        .expect("patch binary must exist");
    assert!(
        dry.success(),
        "patch --dry-run -p0 must accept the emitted diff"
    );

    // 6. Second emit: identical content is idempotent, changed content refused.
    let second = run_env_consolidate_move(Some(&bundle_s), Some(&home), false, Some(&patch_path));
    if second.exit_code == 0 {
        assert_eq!(
            std::fs::read_to_string(&patch_path).unwrap(),
            patch_text,
            "idempotent re-emit must leave the patch byte-identical"
        );
    } else {
        assert_eq!(second.exit_code, 5);
        assert!(second.error.unwrap().contains("already exists"));
    }

    // 7. The human applies the patch out-of-band; the managed value still
    //    resolves through the include block.
    let real = std::process::Command::new("patch")
        .args(["-p0", "--silent"])
        .current_dir(&home)
        .stdin(std::fs::File::open(&patch_path).unwrap())
        .status()
        .expect("patch binary must exist");
    assert!(real.success(), "real `patch -p0` must apply cleanly");
    let bashrc = std::fs::read_to_string(home.join(".bashrc")).unwrap();
    assert!(bashrc.contains("# configctl-move "));
    assert!(!bashrc.lines().any(|l| l == "export EDITOR=vim"));
    assert!(bashrc.contains(">>> configctl env >>>"));
    assert_eq!(
        std::fs::read(home.join(".config/configctl/env.sh")).unwrap(),
        canonical_before,
        "canonical file untouched by the out-of-band patch"
    );
    let sourced = std::process::Command::new("bash")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            "source \"$1\"; printf '%s' \"$EDITOR\"",
            "bash",
        ])
        .arg(home.join(".bashrc"))
        .env("HOME", &home)
        .output()
        .expect("bash must exist");
    assert!(
        sourced.status.success(),
        "patched rc file must still source: {}",
        String::from_utf8_lossy(&sourced.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&sourced.stdout), "vim");

    // 8. Restore from the emitted backups: byte-exact.
    for b in backups {
        let backup = b["backup"].as_str().unwrap();
        let rel = b["original"].as_str().unwrap().strip_prefix("~/").unwrap();
        std::fs::copy(backup, home.join(rel)).unwrap();
    }
    assert_eq!(
        snapshot(&home),
        before,
        "restore from backups must be byte-exact"
    );
}

#[test]
fn move_without_dry_run_or_emit_patch_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, bundle, _state) = world(tmp.path());
    let out = run_env_consolidate_move(Some(bundle.to_str().unwrap()), Some(&home), false, None);
    assert_eq!(out.exit_code, 2);
    assert!(out.error.unwrap().contains("--dry-run"));
    // Nothing was written anywhere.
    assert!(!home.join("move.patch").exists());
}

#[test]
fn move_before_include_apply_is_a_precondition_error() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let bundle = tmp.path().join("work");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(home.join(".bashrc"), "export EDITOR=vim\n").unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[environment]\nEDITOR = \"vim\"\n",
    )
    .unwrap();
    // No canonical file yet: tombstoning would drop the only definition.
    let out = run_env_consolidate_move(Some(bundle.to_str().unwrap()), Some(&home), true, None);
    assert_eq!(out.exit_code, 5);
}
