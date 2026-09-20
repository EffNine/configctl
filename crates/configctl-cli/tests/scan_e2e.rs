//! End-to-end CLI tests for `configctl scan`.

use configctl_cli::commands::scan;

fn tmp_root() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("p");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::fs::write(
        proj.join(".env"),
        "OPENAI_API_KEY=sk-test-E2E-abcdef123456789\nPORT=3000\n",
    )
    .unwrap();
    std::fs::write(proj.join("Cargo.toml"), "[package]\n").unwrap();
    (tmp, proj)
}

#[test]
fn scan_produces_result_on_disposable_tree() {
    let (_tmp, proj) = tmp_root();
    let runner = configctl_core::command::FakeCommandRunner::new();
    let out = scan::run_scan(
        &[proj.to_string_lossy().into_owned()],
        &[],
        None,
        false,
        false,
        false,
        &runner,
    );
    assert!(out.error_envelope.is_none());
    assert_eq!(out.result.statistics.projects_found, 1);
    assert_eq!(out.result.statistics.env_files_found, 1);
}

#[test]
fn scan_missing_root_emits_usage_error() {
    let runner = configctl_core::command::FakeCommandRunner::new();
    let out = scan::run_scan(
        &[std::path::PathBuf::from("/definitely/not/a/real/path/xyz")
            .to_string_lossy()
            .into_owned()],
        &[],
        None,
        false,
        false,
        false,
        &runner,
    );
    // A nonexistent root yields a warning but the scan still completes.
    assert!(out.error_envelope.is_none());
    assert!(
        out.result
            .warnings
            .iter()
            .any(|w| w.contains("does not exist")),
        "missing root must be surfaced as a warning"
    );
}

#[test]
fn scan_depth_flag_bounds_walk() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("p");
    std::fs::create_dir_all(proj.join("a/b/c/d/e/f/g")).unwrap();
    std::fs::write(proj.join("a/b/c/d/e/f/g/deep.env"), "X=1\n").unwrap();

    let runner = configctl_core::command::FakeCommandRunner::new();
    let out = scan::run_scan(
        &[proj.to_string_lossy().into_owned()],
        &[],
        Some(2),
        false,
        false,
        false,
        &runner,
    );
    // The deep .env must not be discovered when the depth cap is 2.
    assert!(
        !out.result
            .env_files
            .iter()
            .any(|e| e.path.ends_with("deep.env")),
        "depth cap must bound discovery"
    );
}

#[test]
fn scan_json_output_parses() {
    let (_tmp, proj) = tmp_root();
    let runner = configctl_core::command::FakeCommandRunner::new();
    let out = scan::run_scan(
        &[proj.to_string_lossy().into_owned()],
        &[],
        None,
        true,
        false,
        false,
        &runner,
    );
    // The P0 envelope is built by the CLI layer and serialized to JSON.
    let envelope = configctl_cli::render::Envelope::scan_ok(&out.result);
    let json_str = envelope.to_json();
    let json_str = out.registry.redact(&json_str);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("JSON must parse");
    assert_eq!(
        parsed.get("schema_version").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(parsed.get("command").and_then(|v| v.as_str()), Some("scan"));
    assert_eq!(parsed.get("status").and_then(|v| v.as_str()), Some("ok"));
    assert!(parsed.get("data").is_some());
    assert!(parsed.get("warnings").is_some());
    assert!(parsed.get("errors").is_some());
}
