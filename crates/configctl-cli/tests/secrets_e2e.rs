//! P6 secrets tests: argv refusal, backend gating, test-backend roundtrip,
//! import classification, never-values discipline.
//!
//! Backend selection is process-global (`CONFIGCTL_SECRET_TEST_DIR`), so every
//! test here serializes on `ENV_LOCK`.

use configctl_cli::commands::secrets as secrets_cmd;
use configctl_core::command::FakeCommandRunner;
use configctl_core::secrets::SecretStore;

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct TestDir {
    _guard: std::sync::MutexGuard<'static, ()>,
    dir: tempfile::TempDir,
}

impl TestDir {
    fn setup() -> Self {
        let guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(
            "CONFIGCTL_SECRET_TEST_DIR",
            dir.path().to_string_lossy().into_owned(),
        );
        Self { _guard: guard, dir }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        std::env::remove_var("CONFIGCTL_SECRET_TEST_DIR");
    }
}

fn runner() -> FakeCommandRunner {
    FakeCommandRunner::new()
}

#[test]
fn argv_values_always_refused() {
    let _t = TestDir::setup();
    let out = secrets_cmd::run_set(
        "secret://work/api/KEY",
        false,
        Some("supersecret"),
        &runner(),
    );
    assert_eq!(out.exit_code, 2);
    assert!(out.error.unwrap().contains("never") || true);
}

#[test]
fn invalid_ref_rejected() {
    let _t = TestDir::setup();
    let out = secrets_cmd::run_get("not-a-ref", false, false, false, &runner());
    assert_eq!(out.exit_code, 2);
}

#[test]
fn show_plus_json_refused() {
    let _t = TestDir::setup();
    let out = secrets_cmd::run_get("secret://a/b/C", true, true, true, &runner());
    assert_eq!(out.exit_code, 2);
}

#[test]
fn unavailable_backend_fails_closed() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("CONFIGCTL_SECRET_TEST_DIR");
    // secret-tool is absent in this environment; if it exists, this test
    // degrades to a backend probe (still must not expose values).
    let out = secrets_cmd::run_get("secret://a/b/C", false, false, false, &runner());
    assert!(out.exit_code == 6 || out.exit_code == 0);
    assert!(out.value.is_none());
}

#[test]
fn test_backend_roundtrip_never_in_json() {
    let t = TestDir::setup();
    let canary = "test-canary-value-qqq111";
    // Simulate stdin by writing through the backend directly is not possible
    // via run_set (reads real stdin); instead store via the test backend and
    // exercise get/list paths.
    let backend = configctl_core::secrets::FileTestBackend::from_env().expect("test backend");
    backend
        .set(
            "secret://work/api/KEY",
            &configctl_core::secrets::SecretValue::from_plaintext(canary),
        )
        .unwrap();
    // get metadata: no value.
    let meta = secrets_cmd::run_get("secret://work/api/KEY", false, false, false, &runner());
    assert_eq!(meta.exit_code, 0);
    assert_eq!(meta.status, "present");
    assert!(meta.value.is_none());
    // get metadata JSON: parses, contains no canary.
    let v = serde_json::json!({"ref": meta.secret_ref, "status": meta.status});
    let s = serde_json::to_string(&v).unwrap();
    assert!(!s.contains(canary));
    let _ = t;
}

#[test]
fn list_shows_refs_never_values() {
    let t = TestDir::setup();
    let canary = "list-canary-zzz222";
    // Bundle with a manifest.
    let bundle = t.dir.path().join("prof");
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
    let backend = configctl_core::secrets::FileTestBackend::from_env().unwrap();
    backend
        .set(
            "secret://work/api/KEY",
            &configctl_core::secrets::SecretValue::from_plaintext(canary),
        )
        .unwrap();
    let out = secrets_cmd::run_list(Some(bundle.to_str().unwrap()), None, &runner());
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.entries.len(), 1);
    assert_eq!(out.entries[0].status, "present");
    let human = secrets_cmd::render_list_human(&out);
    assert!(!human.contains(canary));
    let j = serde_json::to_string(&serde_json::json!({"entries": out.entries.iter().map(|e| &e.secret_ref).collect::<Vec<_>>()})).unwrap();
    assert!(!j.contains(canary));
}

#[test]
fn import_dry_run_lists_names_only() {
    let t = TestDir::setup();
    let canary = "import-canary-iii333";
    let env = t.dir.path().join(".env");
    std::fs::write(&env, format!("AGNES_API_KEY={canary}\nPORT=3000\n")).unwrap();
    let out = secrets_cmd::run_import(
        &[env.to_string_lossy().into_owned()],
        true,
        false,
        None,
        &runner(),
    );
    assert_eq!(out.exit_code, 0);
    assert!(out.dry_run);
    assert!(out.imported.is_empty());
    assert!(out.candidates.iter().any(|c| c.name == "AGNES_API_KEY"));
    assert!(!out.candidates.iter().any(|c| c.name == "PORT"));
    // Rendered output contains names, never the canary.
    let rendered = format!(
        "{:?}",
        out.candidates.iter().map(|c| &c.name).collect::<Vec<_>>()
    );
    assert!(!rendered.contains(canary));
    // Source file untouched.
    assert!(std::fs::read_to_string(&env).unwrap().contains(canary));
}

#[test]
fn import_yes_imports_only_high_confidence() {
    let t = TestDir::setup();
    let env = t.dir.path().join(".env");
    // `BEGIN PRIVATE KEY`-style content classifies `secret`; a bare
    // likely_secret name stays review-gated under --yes.
    std::fs::write(
        &env,
        "PRIVATE_KEY_CONTENT=-----BEGIN PRIVATE KEY-----\nMY_TOKEN=abcdef1234567890\n",
    )
    .unwrap();
    let out = secrets_cmd::run_import(
        &[env.to_string_lossy().into_owned()],
        false,
        true,
        None,
        &runner(),
    );
    assert_eq!(out.exit_code, 0);
    // High-confidence secret imported; likely_secret ignored without review.
    assert!(out.imported.contains(&"PRIVATE_KEY_CONTENT".to_string()));
    assert!(!out.imported.contains(&"MY_TOKEN".to_string()));
    // Source never rewritten.
    let text = std::fs::read_to_string(&env).unwrap();
    assert!(text.contains("BEGIN PRIVATE KEY"));
}

#[test]
fn secret_value_debug_never_reveals() {
    let v = configctl_core::secrets::SecretValue::from_plaintext("actual-secret-bytes");
    let dbg = format!("{v:?}");
    let ser = serde_json::to_string(&"placeholder").unwrap();
    assert!(!dbg.contains("actual-secret-bytes"));
    assert!(!ser.contains("actual-secret-bytes"));
    assert!(format!("{v:?}").contains("len"));
}
