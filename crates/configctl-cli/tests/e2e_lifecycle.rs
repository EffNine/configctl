//! P8 realistic end-to-end fixture: a disposable Linux developer home.
//!
//! ```text
//! fake-home/
//! ├── .gitconfig
//! ├── .editorconfig
//! └── projects/
//!     ├── rust-app/  (Cargo.toml, .env, .env.example)
//!     └── node-app/  (package.json, .env.local)
//! ```
//!
//! Lifecycle: scan → capture → validate → plan → apply → verify MATCH →
//! drift → verify DRIFT → re-plan → apply → verify MATCH → rollback → verify
//! expected rollback state. Never the real HOME.

use configctl_core::apply::{apply_plan, ApplyOptions};
use configctl_core::command::FakeCommandRunner;

fn build_fake_home() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("fake-home");
    let rust_app = home.join("projects/rust-app");
    let node_app = home.join("projects/node-app");
    std::fs::create_dir_all(&rust_app).unwrap();
    std::fs::create_dir_all(&node_app).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Dev\n\temail = dev@example.com\n",
    )
    .unwrap();
    std::fs::write(home.join(".editorconfig"), "root = true\n").unwrap();
    std::fs::write(
        rust_app.join("Cargo.toml"),
        "[package]\nname = \"rust-app\"\n",
    )
    .unwrap();
    std::fs::write(rust_app.join(".env"), "PORT=3000\nAPP_TOKEN=aaa111bbb222\n").unwrap();
    std::fs::write(rust_app.join(".env.example"), "PORT=\nAPP_TOKEN=\n").unwrap();
    std::fs::write(node_app.join("package.json"), "{\"name\":\"node-app\"}\n").unwrap();
    std::fs::write(node_app.join(".env.local"), "DEBUG=false\n").unwrap();
    let state = tmp.path().join("state");
    (tmp, home, state)
}

#[test]
fn full_safe_lifecycle() {
    let (_tmp, home, state) = build_fake_home();
    let projects = home.join("projects");
    // Bundle dir basename must equal the profile name (spoofing guard).
    let bundle = _tmp.path().join("dev");
    let runner = FakeCommandRunner::new();
    let yes = |_: &configctl_core::plan::Plan| true;

    // 1. scan (read-only).
    let scan = configctl_cli::commands::scan::run_scan(
        &[projects.to_string_lossy().into_owned()],
        &[],
        None,
        false,
        false,
        false,
        &runner,
    );
    assert!(scan.error_envelope.is_none());
    assert!(scan.result.projects.len() >= 2);

    // 2. capture into the bundle (writes only inside bundle).
    // Capture uses dirs::home_dir for $HOME — override by capturing with the
    // core pipeline? Use the CLI entry with --from and --output; the home
    // allowlist reads the *real* HOME. For hermeticity, temporarily point
    // HOME at the fake home (process-global: serialize via a private lock).
    let cap = {
        let _lock = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", &home);
        let out = configctl_cli::commands::capture::run_capture(
            Some("dev"),
            &[projects.to_string_lossy().into_owned()],
            &[],
            Some(bundle.to_string_lossy().as_ref()),
            true,
            None,
            false,
            None,
            &runner,
        );
        match prev {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        out
    };
    assert!(
        cap.error_envelope.is_none(),
        "{:?}",
        cap.error_envelope.map(|e| e.to_json())
    );
    assert!(bundle.join("profile.toml").exists());

    // 3. validate.
    let errors = configctl_cli::commands::profile::run_validate(bundle.to_str().unwrap());
    assert!(errors.is_empty(), "{errors:?}");

    // Simulate a fresh machine: the captured dotfiles are missing here, so
    // the plan has real work (CREATE) instead of a trivial noop.
    std::fs::remove_file(home.join(".gitconfig")).unwrap();
    std::fs::remove_file(home.join(".editorconfig")).unwrap();

    // 4. plan (run with fake home so targets expand there).
    let plan_home_guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prev_home = std::env::var_os("HOME");
    std::env::set_var("HOME", &home);
    let planned = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("e2e-1"),
        Some(1000),
    );
    assert!(planned.error.is_none());
    let plan = planned.plan.unwrap();
    assert!(!configctl_core::plan::is_noop(&plan));

    // 5. approve (explicit --yes path) + apply to the disposable target.
    apply_plan(
        &state,
        "e2e-1",
        &home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("apply");

    // 6. verify MATCH.
    let ver = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &runner,
    );
    assert_eq!(ver.exit_code, 0, "{:?}", ver.report.map(|r| r.results));

    // 7. introduce drift.
    let gitconfig = std::fs::read_to_string(home.join(".gitconfig")).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        format!("{gitconfig}\n[extra]\n\tfoo = bar\n"),
    )
    .unwrap();

    // 8. verify DRIFT.
    let ver2 = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &runner,
    );
    assert_eq!(ver2.exit_code, 3);

    // 9. re-plan + apply (needs --adopt? No: file is managed now → update).
    let planned2 = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("e2e-2"),
        Some(2000),
    );
    assert!(planned2.error.is_none());
    assert!(planned2.plan.as_ref().unwrap().conflicts.is_empty());
    apply_plan(
        &state,
        "e2e-2",
        &home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("re-apply");

    // 10. verify MATCH again.
    let ver3 = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &runner,
    );
    assert_eq!(ver3.exit_code, 0);

    // 11. rollback the re-apply → drift returns (pre-re-apply content had the
    // extra stanza).
    let rb = configctl_cli::commands::rollback::run_rollback(
        Some("e2e-2"),
        None,
        false,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        false,
        &runner,
    );
    assert_eq!(rb.exit_code, 0);
    let content = std::fs::read_to_string(home.join(".gitconfig")).unwrap();
    assert!(content.contains("[extra]"));

    // 12. verify shows DRIFT again (expected rollback state).
    let ver4 = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &runner,
    );
    assert_eq!(ver4.exit_code, 3);

    // Restore HOME.
    match prev_home {
        Some(v) => std::env::set_var("HOME", v),
        None => std::env::remove_var("HOME"),
    }
    drop(plan_home_guard);
}

static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
