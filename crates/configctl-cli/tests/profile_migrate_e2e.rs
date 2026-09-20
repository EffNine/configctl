//! Profile migration tests (v1 bundle -> v2, disposable dirs).

use configctl_cli::commands::profile;

#[test]
fn migrate_v1_bundle_to_v2_rewrites_schema() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("legacy");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("profile.toml"),
        "schema_version = 1\nname = \"legacy\"\n\n[packages]\napt = [\"git\"]\n",
    )
    .unwrap();

    let msg = profile::run_migrate(dir.to_string_lossy().as_ref(), 2).expect("migrate");
    assert!(msg.contains("migrated to schema_version 2"));
    let text = std::fs::read_to_string(dir.join("profile.toml")).unwrap();
    assert!(text.contains("schema_version = 2"));
    // v1 content preserved.
    assert!(text.contains("\"git\""));

    // Second run is a no-op report.
    let msg2 = profile::run_migrate(dir.to_string_lossy().as_ref(), 2).expect("idempotent");
    assert!(msg2.contains("already at schema_version 2"));

    // Invalid target rejected.
    assert!(profile::run_migrate(dir.to_string_lossy().as_ref(), 99).is_err());
}
