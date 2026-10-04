//! envmap file-level corpus: the parser's file readers must skip unreadable rc
//! files gracefully (never fatal), and secret canaries from real rc fixtures
//! must never reach `env explain` output in any form.
//!
//! Fixtures live with their owner (`configctl-core/tests/fixtures/envmap/`);
//! this suite exercises the file-reading layer (`run_env_explain`) over them.

use configctl_cli::commands::env::run_env_explain;
use std::path::PathBuf;

fn core_fixture(name: &str) -> String {
    let p: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "configctl-core",
        "tests",
        "fixtures",
        "envmap",
        name,
    ]
    .iter()
    .collect();
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("core fixture {name} unreadable at {}: {e:?}", p.display()))
}

const CANARIES: &[&str] = &["ghp_TESTCANARY0000000001", "wJalrXUtnFEMI_TESTCANARY2"];

#[test]
fn permission_denied_bashrc_skips_gracefully() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bashrc = home.join(".bashrc");
    std::fs::write(&bashrc, core_fixture("bashrc_ubuntu")).unwrap();
    // A healthy sibling proves a partial read still succeeds (skip one file,
    // not the whole map).
    std::fs::write(home.join(".profile"), "export SURVIVOR=yes\n").unwrap();

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&bashrc, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root ignores permission bits: probe the actual readability (same
    // discipline as the discovery permission test) instead of assuming.
    let actually_denied = std::fs::File::open(&bashrc).is_err();
    let out = run_env_explain(Some(&home));
    std::fs::set_permissions(&bashrc, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert!(out.error.is_none(), "unreadable rc must not be fatal");
    assert_eq!(out.exit_code, 0);
    if !actually_denied {
        eprintln!("SKIP strict assertions: running with privilege; mode bits not enforced");
        return;
    }
    let sources = out.data["sources"].as_array().unwrap();
    assert!(
        !sources.iter().any(|s| s["path"] == "~/.bashrc"),
        "unreadable .bashrc must be skipped, not partial-parsed"
    );
    assert!(
        sources.iter().any(|s| s["path"] == "~/.profile"),
        "readable siblings must still be explained"
    );
    for c in CANARIES {
        assert!(!out.text.contains(c), "canary leaked into text: {c}");
        assert!(
            !out.data.to_string().contains(c),
            "canary leaked into JSON: {c}"
        );
    }
}

#[test]
fn explain_over_corpus_never_leaks_canaries() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join(".bashrc"), core_fixture("bashrc_ubuntu")).unwrap();
    std::fs::write(home.join(".zshrc"), core_fixture("zshrc")).unwrap();
    std::fs::write(home.join(".profile"), core_fixture("profile_path")).unwrap();

    let out = run_env_explain(Some(&home));
    assert!(out.error.is_none());
    assert_eq!(out.exit_code, 0);
    for c in CANARIES {
        assert!(!out.text.contains(c), "canary leaked into text: {c}");
        assert!(
            !out.data.to_string().contains(c),
            "canary leaked into JSON: {c}"
        );
    }
    // Secrets are still REPORTED by name (classification works), values gone.
    let secrets = out.data["secret_names"].as_array().unwrap();
    let names: Vec<&str> = secrets.iter().filter_map(|s| s.as_str()).collect();
    assert!(names.contains(&"GITHUB_TOKEN"));
    assert!(names.contains(&"AWS_SECRET_ACCESS_KEY"));
    // Managed winners still resolve across the corpus.
    let prec = out.data["precedence"].as_array().unwrap();
    assert!(prec.iter().any(|p| p["name"] == "EDITOR"));
}
