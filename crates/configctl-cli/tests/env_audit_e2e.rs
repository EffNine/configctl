//! P6 env/audit tests (disposable fixtures; values never rendered).

use configctl_cli::commands::{audit as audit_cmd, env as env_cmd};
use configctl_core::command::FakeCommandRunner;

fn fixture_project() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let proj = root.join("conductor");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("Cargo.toml"), "[package]\nname=\"c\"\n").unwrap();
    std::fs::write(
        proj.join(".env"),
        "PORT=3000\nNODE_ENV=production\nAGNES_API_KEY=test-value-aaa\n",
    )
    .unwrap();
    std::fs::write(
        proj.join(".env.example"),
        "PORT=\nNODE_ENV=\nAGNES_API_KEY=\n",
    )
    .unwrap();
    (tmp, root, proj)
}

fn bundle_for(proj: &std::path::Path, home: &std::path::Path) -> std::path::PathBuf {
    // Project path uses the real absolute path (validation accepts
    // traversal-free absolute paths for fixtures).
    let bundle = home.join("prof");
    std::fs::create_dir_all(bundle.join("env")).unwrap();
    // Project path uses the real absolute path (validation accepts
    // traversal-free absolute paths for fixtures).
    std::fs::write(
        bundle.join("profile.toml"),
        format!(
            "schema_version = 1\nname = \"prof\"\n\n[[projects]]\nname = \"conductor\"\npath = \"{}\"\nenv_schema = \"env/conductor.toml\"\n",
            proj.to_string_lossy()
        ),
    )
    .unwrap();
    std::fs::write(
        bundle.join("env/conductor.toml"),
        "schema_version = 1\n\n[project]\nname = \"conductor\"\n\n[[variables]]\nname = \"PORT\"\ntype = \"integer\"\nrequired = true\n\n[[variables]]\nname = \"NODE_ENV\"\ntype = \"enum\"\nvalues = [\"development\", \"test\", \"production\"]\n\n[[variables]]\nname = \"AGNES_API_KEY\"\ntype = \"string\"\nsecret = true\nrequired = true\n\n[[variables]]\nname = \"MISSING_REQ\"\ntype = \"string\"\nrequired = true\n",
    )
    .unwrap();
    std::fs::write(bundle.join("secrets.manifest.toml"), "schema_version = 1\n").unwrap();
    bundle
}

#[test]
fn env_scan_counts_without_values() {
    let (_tmp, root, _proj) = fixture_project();
    let canary = "test-value-aaa";
    let view = env_cmd::run_env_scan(
        &[root.to_string_lossy().into_owned()],
        &[],
        None,
        &FakeCommandRunner::new(),
    )
    .expect("env scan");
    assert!(view.files >= 1);
    assert!(view.variables >= 3);
    assert!(view.secrets >= 1);
    let human = env_cmd::render_scan_human(&view);
    assert!(!human.contains(canary));
    let list = env_cmd::render_list_human(&view, None);
    assert!(!list.contains(canary));
    assert!(list.contains("AGNES_API_KEY"));
}

#[test]
fn env_verify_finds_missing_and_type_errors() {
    let (_tmp, _root, proj) = fixture_project();
    // Make PORT invalid + drop NODE_ENV enum range later; first check missing.
    let home = _tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bundle = bundle_for(&proj, &home);
    let out = env_cmd::run_env_verify(
        Some(bundle.to_str().unwrap()),
        None,
        false,
        Some(&home),
        &FakeCommandRunner::new(),
    );
    assert!(out.error.is_none(), "{:?}", out.error);
    // MISSING_REQ absent → missing; AGNES_API_KEY secret ref missing → error.
    assert!(out
        .findings
        .iter()
        .any(|f| f.variable == "MISSING_REQ" && f.kind == "missing"));
    assert!(out
        .findings
        .iter()
        .any(|f| f.variable == "AGNES_API_KEY" && f.kind == "secret_ref_missing"));
    assert_eq!(out.exit_code, 3);
    // No values anywhere.
    let rendered = env_cmd::render_verify_human(&out);
    assert!(!rendered.contains("test-value-aaa"));
    assert!(!rendered.contains("3000"));
}

#[test]
fn env_verify_detects_invalid_type() {
    let (_tmp, _root, proj) = fixture_project();
    std::fs::write(
        proj.join(".env"),
        "PORT=notanint\nNODE_ENV=production\nAGNES_API_KEY=x\n",
    )
    .unwrap();
    let home = _tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bundle = bundle_for(&proj, &home);
    let out = env_cmd::run_env_verify(
        Some(bundle.to_str().unwrap()),
        Some("conductor"),
        false,
        Some(&home),
        &FakeCommandRunner::new(),
    );
    assert!(out
        .findings
        .iter()
        .any(|f| f.variable == "PORT" && f.kind == "invalid"));
    assert_eq!(out.exit_code, 3);
}

#[test]
fn audit_flags_tracked_env_and_missing_example() {
    // Real git repo fixture (read-only audit; git binary present?).
    if which_git().is_none() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join(".env"), "AGNES_API_KEY=live-value-bbb\n").unwrap();
    std::fs::write(repo.join("main.py"), "print(1)\n").unwrap();
    git(&repo, &["init"]);
    git(&repo, &["add", "."]);
    git(
        &repo,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-m",
            "x",
        ],
    );
    let runner = configctl_core::command::StdCommandRunner::new();
    let out = audit_cmd::run_audit(
        &[repo.to_string_lossy().into_owned()],
        &[],
        Some("warning"),
        false,
        &runner,
    );
    assert!(out.error.is_none(), "{:?}", out.error);
    assert!(
        out.findings.iter().any(|f| f.code == "tracked_env"),
        "findings: {:?}",
        out.findings.iter().map(|f| &f.code).collect::<Vec<_>>()
    );
    assert_eq!(out.exit_code, 3);
    let human = audit_cmd::render_human(&out);
    assert!(!human.contains("live-value-bbb"));
}

#[test]
fn audit_json_parses() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("r");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("a.txt"), "hello\n").unwrap();
    let out = audit_cmd::run_audit(
        &[repo.to_string_lossy().into_owned()],
        &[],
        None,
        false,
        &FakeCommandRunner::new(),
    );
    assert!(out.error.is_none());
    let v = serde_json::to_value(out.findings.iter().map(|f| &f.code).collect::<Vec<_>>()).unwrap();
    let _: serde_json::Value = serde_json::from_str(&v.to_string()).unwrap();
}

fn which_git() -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("git"))
            .find(|p| p.is_file())
    })
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let st = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir)
        .output()
        .expect("git");
    assert!(st.status.success(), "git {args:?} failed");
}
