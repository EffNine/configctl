//! `env explain` + `env consolidate --dry-run` end-to-end over a temp home.
//!
//! These are read-only: the tests assert that no value of a secret-like
//! variable ever reaches human or JSON output, and that `consolidate` never
//! writes anything.

use configctl_cli::commands::env::{run_env_consolidate, run_env_explain};
use std::path::Path;

const SECRET_VALUE: &str = "ghp_zzzzzzzzzzzzzzzzzzzz";

fn home_with(dir: &Path, bashrc: &str, profile: &str, envd: Option<&str>) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(".bashrc"), bashrc).unwrap();
    std::fs::write(dir.join(".profile"), profile).unwrap();
    if let Some(conf) = envd {
        let d = dir.join(".config/environment.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("90-configctl.conf"), conf).unwrap();
    }
}

#[test]
fn explain_reports_sources_conflicts_and_never_leaks_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    home_with(
        &home,
        &format!(
            "export EDITOR=nano\n\
             export PATH=\"$PATH:$HOME/.local/bin\"\n\
             export GITHUB_TOKEN={SECRET_VALUE}\n"
        ),
        "export EDITOR=emacs\nexport LANG=en_US.UTF-8\n",
        Some("EDITOR=code\n"),
    );

    let out = run_env_explain(Some(&home));
    assert!(out.error.is_none());
    assert_eq!(out.exit_code, 0);

    // Human output mentions the files and the special/secret handling.
    assert!(out.text.contains("~/.bashrc"));
    assert!(out.text.contains("left alone"));
    assert!(out.text.contains("GITHUB_TOKEN"));

    // The secret value must never appear anywhere in the output.
    assert!(!out.text.contains(SECRET_VALUE));
    assert!(!out.data.to_string().contains(SECRET_VALUE));

    // EDITOR is declared in three sources with three values -> a conflict.
    let conflicts = out.data["conflicts"].as_array().unwrap();
    assert!(conflicts.iter().any(|c| c["name"] == "EDITOR"));

    // The value the shell would actually see is reported as precedence.
    let prec = out.data["precedence"].as_array().unwrap();
    assert!(prec
        .iter()
        .any(|p| p["name"] == "LANG" && p["value"] == "en_US.UTF-8"));
}

#[test]
fn consolidate_dry_run_previews_without_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    home_with(
        &home,
        "export EDITOR=nano\nexport LANG=en_US.UTF-8\n",
        "",
        None,
    );

    let out = run_env_consolidate(&[], "include", true, Some(&home));
    assert!(out.error.is_none(), "unexpected error: {:?}", out.error);
    assert_eq!(out.exit_code, 0);
    assert!(out.text.contains("Dry run"));
    assert!(out.data["dry_run"] == true);

    // Canonical content is sorted and contains the settings.
    let canonical = out.data["canonical_content"].as_str().unwrap();
    assert!(canonical.contains("EDITOR=nano"));
    assert!(canonical.contains("LANG=en_US.UTF-8"));
    let e = canonical.find("EDITOR=").unwrap();
    let l = canonical.find("LANG=").unwrap();
    assert!(e < l);

    // Nothing was written: the canonical file must not exist.
    assert!(!home.join(".config/configctl/env.sh").exists());
    // The rc file is unchanged (no include block appended).
    let bashrc = std::fs::read_to_string(home.join(".bashrc")).unwrap();
    assert!(!bashrc.contains(">>> configctl env >>>"));
}

#[test]
fn consolidate_without_dry_run_refuses_to_write() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    home_with(&home, "export EDITOR=nano\n", "", None);

    let out = run_env_consolidate(&[], "include", false, Some(&home));
    assert!(out.error.is_some());
    assert_eq!(out.exit_code, 2);
    assert!(!home.join(".config/configctl/env.sh").exists());
}

#[test]
fn consolidate_requires_var_for_conflicting_settings() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    home_with(&home, "export EDITOR=nano\n", "export EDITOR=vim\n", None);

    // Auto-picking between conflicting unmanaged values is refused.
    let refused = run_env_consolidate(&[], "include", true, Some(&home));
    assert_eq!(refused.exit_code, 5);
    assert!(refused.error.unwrap().contains("EDITOR"));

    // Explicit selection is accepted.
    let chosen = run_env_consolidate(&["EDITOR".to_string()], "include", true, Some(&home));
    assert!(chosen.error.is_none());
    assert_eq!(chosen.exit_code, 0);
}
