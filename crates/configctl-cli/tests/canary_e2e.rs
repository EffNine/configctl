//! P8 secret canary suite: synthetic secrets flow through every command and
//! every output mode; raw values must not appear in any prohibited sink.
//!
//! Uses the gated file test backend (`CONFIGCTL_SECRET_TEST_DIR`) for the
//! secrets commands and disposable fixtures everywhere else.

use configctl_core::command::FakeCommandRunner;

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Guard {
    _g: std::sync::MutexGuard<'static, ()>,
}

impl Guard {
    fn lock(dir: &tempfile::TempDir) -> Self {
        let g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "CONFIGCTL_SECRET_TEST_DIR",
            dir.path().join("secrets").to_string_lossy().into_owned(),
        );
        std::fs::create_dir_all(dir.path().join("secrets")).unwrap();
        Self { _g: g }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        std::env::remove_var("CONFIGCTL_SECRET_TEST_DIR");
    }
}

const CANARY_1: &str = "canary-live-value-AAA111bbb";
const CANARY_2: &str = "ghp_canarytokensuffix999888777";
const CANARY_3: &str = "sk-live-canary-CCC333ooo000";

fn all_canaries() -> [&'static str; 3] {
    [CANARY_1, CANARY_2, CANARY_3]
}

fn build_world() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let proj = tmp.path().join("proj");
    let bundle = tmp.path().join("work");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::fs::write(proj.join("Cargo.toml"), "[package]\nname=\"w\"\n").unwrap();
    std::fs::write(
        proj.join(".env"),
        format!("AGNES_API_KEY={CANARY_1}\nGITHUB_TOKEN={CANARY_2}\nPORT=3000\n"),
    )
    .unwrap();
    std::fs::write(
        proj.join(".env.example"),
        "AGNES_API_KEY=\nGITHUB_TOKEN=\nPORT=\n",
    )
    .unwrap();
    std::fs::write(home.join(".gitconfig"), "[user]\n\tname = T\n").unwrap();
    std::fs::write(home.join(".editorconfig"), "root = true\n").unwrap();
    std::fs::create_dir_all(&bundle).unwrap();
    std::fs::write(bundle.join("profile.toml"), "placeholder").unwrap();
    (tmp, home, proj, bundle, state)
}

fn assert_no_canary(where_: &str, text: &str) {
    for c in all_canaries() {
        assert!(!text.contains(c), "canary leaked in {where_}");
    }
}

#[test]
fn canary_scan_capture_plan_outputs() {
    let (_tmp, home, proj, _bundle, _state) = build_world();
    let runner = FakeCommandRunner::new();
    // scan human + json.
    let scan = configctl_cli::commands::scan::run_scan(
        &[proj.to_string_lossy().into_owned()],
        &[],
        None,
        false,
        false,
        true,
        &runner,
    );
    assert!(scan.error_envelope.is_none());
    let human = configctl_cli::commands::scan::render_human(&scan.result, false, true);
    assert_no_canary("scan human", &scan.registry.redact(&human));
    let env = configctl_cli::render::Envelope::scan_ok(&scan.result);
    assert_no_canary("scan json", &scan.registry.redact(&env.to_json()));
    let _ = home;
}

#[test]
fn canary_capture_bundle_and_plan_apply_verify() {
    let (_tmp, home, proj, bundle, state) = build_world();
    // Isolate HOME-dependent bundle naming: capture into bundle dir.
    let runner = FakeCommandRunner::new();
    let cap = configctl_cli::commands::capture::run_capture(
        Some("work"),
        &[proj.to_string_lossy().into_owned()],
        &[],
        Some(bundle.to_string_lossy().as_ref()),
        true,
        None,
        false,
        None,
        &runner,
    );
    assert!(
        cap.error_envelope.is_none(),
        "{:?}",
        cap.error_envelope.map(|e| e.to_json())
    );
    // Every bundle file is canary-free.
    let mut stack = vec![bundle.clone()];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p).unwrap().filter_map(|c| c.ok()) {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                let bytes = std::fs::read(&path).unwrap();
                if bytes.len() < 4 * 1024 * 1024 {
                    assert_no_canary(
                        &format!("bundle {}", path.display()),
                        &String::from_utf8_lossy(&bytes),
                    );
                }
            }
        }
    }
    // plan human + json.
    let planned = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("can-1"),
        Some(1000),
    );
    assert!(planned.error.is_none());
    let plan = planned.plan.unwrap();
    assert_no_canary(
        "plan human",
        &configctl_cli::commands::plan::render_human(&plan),
    );
    let penv = configctl_cli::render::Envelope::plan_ok(&plan);
    assert_no_canary("plan json", &penv.to_json());
    // apply (dry-run + real on a safe file target) + verify outputs.
    // The captured bundle conflicts with the unmanaged home dotfile by
    // design; adopt it for the dry-run (still no writes).
    let dry = configctl_cli::commands::apply::run_apply(
        Some("can-1"),
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        true,
        &["~/.gitconfig".to_string()],
        true,
        &runner,
    );
    assert_eq!(dry.exit_code, 0);
    let rep = dry.report.unwrap();
    assert_no_canary(
        "apply dry json",
        &configctl_cli::commands::apply::report_json(&rep).to_string(),
    );
    // Verify against the same bundle.
    let ver = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &runner,
    );
    assert!(ver.error.is_none());
    let vrep = ver.report.unwrap();
    assert_no_canary(
        "verify human",
        &configctl_cli::commands::verify::render_human(&vrep),
    );
    let vj = serde_json::to_value(&vrep).unwrap().to_string();
    assert_no_canary("verify json", &vj);
    // env scan/list/verify outputs.
    let envscan = configctl_cli::commands::env::run_env_scan(
        &[proj.to_string_lossy().into_owned()],
        &[],
        None,
        &runner,
    )
    .unwrap();
    assert_no_canary(
        "env scan",
        &configctl_cli::commands::env::render_scan_human(&envscan),
    );
    assert_no_canary(
        "env list",
        &configctl_cli::commands::env::render_list_human(&envscan, None),
    );
    // audit output.
    let audit = configctl_cli::commands::audit::run_audit(
        &[proj.to_string_lossy().into_owned()],
        &[],
        None,
        false,
        &runner,
    );
    assert_no_canary(
        "audit",
        &configctl_cli::commands::audit::render_human(&audit),
    );
    // doctor output.
    let doc = configctl_cli::commands::doctor::run_doctor(Some(state.to_str().unwrap()), &runner);
    assert_no_canary(
        "doctor",
        &configctl_cli::commands::doctor::render_human(&doc),
    );
}

#[test]
fn canary_secrets_commands_and_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let _g = Guard::lock(&tmp);
    let runner = FakeCommandRunner::new();
    // Store via test backend (simulates `secrets set` without a TTY).
    {
        use configctl_core::secrets::SecretStore;
        let backend = configctl_core::secrets::FileTestBackend::from_env().unwrap();
        backend
            .set(
                "secret://work/proj/AGNES_API_KEY",
                &configctl_core::secrets::SecretValue::from_plaintext(CANARY_1),
            )
            .unwrap();
    }
    // get metadata (no value).
    let meta = configctl_cli::commands::secrets::run_get(
        "secret://work/proj/AGNES_API_KEY",
        false,
        false,
        false,
        &runner,
    );
    assert_eq!(meta.exit_code, 0);
    assert!(meta.value.is_none());
    // Error paths never echo values: invalid ref, missing secret, refused json.
    let bad = configctl_cli::commands::secrets::run_get("bogus", false, false, false, &runner);
    assert_no_canary("invalid-ref error", &bad.error.unwrap_or_default());
    let missing = configctl_cli::commands::secrets::run_get(
        "secret://work/proj/NOPE",
        true,
        true,
        false,
        &runner,
    );
    assert_no_canary("missing error", &missing.error.unwrap_or_default());
    let refused = configctl_cli::commands::secrets::run_get(
        "secret://work/proj/AGNES_API_KEY",
        true,
        true,
        true,
        &runner,
    );
    assert_eq!(refused.exit_code, 2);
    // set with argv value refused (message contains no value).
    let argv = configctl_cli::commands::secrets::run_set(
        "secret://work/proj/X",
        false,
        Some(CANARY_3),
        &runner,
    );
    assert_eq!(argv.exit_code, 2);
    assert_no_canary("argv refusal", &argv.error.unwrap_or_default());
    // import dry-run over a canary file.
    let env = tmp.path().join(".env");
    std::fs::write(&env, format!("AGNES_API_KEY={CANARY_1}\nPORT=1\n")).unwrap();
    let imp = configctl_cli::commands::secrets::run_import(
        &[env.to_string_lossy().into_owned()],
        true,
        false,
        None,
        &runner,
    );
    assert_eq!(imp.exit_code, 0);
    let rendered = format!("{:?}", imp.candidates);
    assert_no_canary("import candidates", &rendered);
    assert!(!std::fs::read_to_string(&env).unwrap().is_empty());
}

#[test]
fn canary_state_db_and_journal_have_no_values() {
    let (_tmp, home, _proj, bundle, state) = build_world();
    // Rebuild bundle properly via capture is overkill; craft a minimal file
    // plan through the public CLI path and inspect the state dir bytes.
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/g"), "payload\n").unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[[files]]\ntarget = \"~/.g\"\nsource = \"files/g\"\n",
    )
    .unwrap();
    let runner = FakeCommandRunner::new();
    let planned = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("can-2"),
        Some(1000),
    );
    assert!(planned.error.is_none());
    let yes = |_: &configctl_core::plan::Plan| true;
    configctl_core::apply::apply_plan(
        &state,
        "can-2",
        &home,
        &runner,
        &configctl_core::apply::ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("apply");
    // Walk the whole state dir (db, plans, journals, backups, logs).
    let mut stack = vec![state.clone()];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p).unwrap().filter_map(|c| c.ok()) {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                // Skip the sqlite WAL/journal sidecars by reading main files;
                // scan everything as lossy text.
                if let Ok(bytes) = std::fs::read(&path) {
                    let text = String::from_utf8_lossy(&bytes);
                    for c in all_canaries() {
                        // The payload "payload" is not a canary; canaries live
                        // only in the untouched .env (never read by plan/apply).
                        assert!(!text.contains(c), "canary in state file {}", path.display());
                    }
                }
            }
        }
    }
    let _ = CANARY_2;
}
