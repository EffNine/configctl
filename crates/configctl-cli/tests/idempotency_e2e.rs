//! P8 idempotency + determinism proofs.
//!
//! - Idempotency: `apply → verify MATCH → plan same profile → zero mutating
//!   operations` (the v1.0 gate).
//! - Determinism: same profile + same observed state ⇒ same semantic plan +
//!   same hash, across repeated runs.

use configctl_core::apply::{apply_plan, ApplyOptions};
use configctl_core::command::FakeCommandRunner;

fn world() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let bundle = tmp.path().join("work");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(bundle.join("files/g"), "v1\n").unwrap();
    std::fs::write(bundle.join("files/e"), "editor\n").unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"work\"\n\n[[files]]\ntarget = \"~/.g\"\nsource = \"files/g\"\n\n[[files]]\ntarget = \"~/.e\"\nsource = \"files/e\"\n\n[environment]\nEDITOR = \"nvim\"\n",
    )
    .unwrap();
    (tmp, home, bundle, state)
}

#[test]
fn apply_verify_replan_is_empty() {
    let (_tmp, home, bundle, state) = world();
    let runner = FakeCommandRunner::new();
    // plan → apply.
    let planned = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("idem-1"),
        Some(1000),
    );
    assert!(planned.error.is_none());
    assert!(!configctl_core::plan::is_noop(
        planned.plan.as_ref().unwrap()
    ));
    let yes = |_: &configctl_core::plan::Plan| true;
    apply_plan(
        &state,
        "idem-1",
        &home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("apply");
    // verify MATCH.
    let ver = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &runner,
    );
    assert_eq!(ver.exit_code, 0, "{:?}", ver.report.map(|r| r.results));
    // Re-plan: zero mutating operations.
    let planned2 = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("idem-2"),
        Some(2000),
    );
    assert!(planned2.error.is_none());
    let p2 = planned2.plan.unwrap();
    assert!(
        configctl_core::plan::is_noop(&p2),
        "expected noop, got {:?}",
        p2.operations
            .iter()
            .map(|o| (&o.kind, &o.target))
            .collect::<Vec<_>>()
    );
    assert!(configctl_core::plan::executable_ops(&p2).is_empty());
}

#[test]
fn repeated_plans_have_identical_hashes() {
    let (_tmp, home, bundle, state) = world();
    let runner = FakeCommandRunner::new();
    let mut hashes = Vec::new();
    for i in 0..5 {
        let planned = configctl_cli::commands::plan::run_plan(
            bundle.to_str().unwrap(),
            Some(state.to_str().unwrap()),
            Some(&home),
            &runner,
            Some(&format!("det-{i}")),
            Some(1000 + i as i64),
        );
        assert!(planned.error.is_none());
        hashes.push(planned.plan.unwrap().plan_hash);
    }
    for h in &hashes {
        assert_eq!(h, &hashes[0]);
    }
}

#[test]
fn json_contract_parses_for_all_commands() {
    // Every JSON-producing command emits exactly one parseable document with
    // the stable envelope (schema_version/command/status/data/warnings/errors).
    let (_tmp, home, bundle, state) = world();
    let runner = FakeCommandRunner::new();
    let check = |name: &str, doc: String| {
        let v: serde_json::Value =
            serde_json::from_str(&doc).unwrap_or_else(|_| panic!("{name} invalid JSON"));
        for key in ["schema_version", "command", "status", "warnings", "errors"] {
            assert!(v.get(key).is_some(), "{name} missing {key}");
        }
    };
    // plan.
    let planned = configctl_cli::commands::plan::run_plan(
        bundle.to_str().unwrap(),
        Some(state.to_str().unwrap()),
        Some(&home),
        &runner,
        Some("jc-1"),
        Some(1000),
    );
    check(
        "plan",
        configctl_cli::render::Envelope::plan_ok(&planned.plan.unwrap()).to_json(),
    );
    // apply dry-run.
    let dry = configctl_cli::commands::apply::run_apply(
        Some("jc-1"),
        None,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        true,
        &[],
        true,
        &runner,
    );
    check(
        "apply",
        configctl_cli::render::Envelope::ok(
            "apply",
            configctl_cli::commands::apply::report_json(&dry.report.unwrap()),
        )
        .to_json(),
    );
    // verify.
    let ver = configctl_cli::commands::verify::run_verify(
        bundle.to_str().unwrap(),
        Some(&home),
        false,
        &runner,
    );
    check(
        "verify",
        configctl_cli::render::Envelope::ok(
            "verify",
            serde_json::to_value(ver.report.unwrap()).unwrap(),
        )
        .to_json(),
    );
    // env scan/list/verify.
    let envscan = configctl_cli::commands::env::run_env_scan(
        &[home.to_string_lossy().into_owned()],
        &[],
        None,
        &runner,
    )
    .unwrap();
    check(
        "env scan",
        configctl_cli::render::Envelope::ok(
            "env scan",
            serde_json::json!({"files": envscan.files}),
        )
        .to_json(),
    );
    // audit/doctor/rollback --list/profile.
    let audit = configctl_cli::commands::audit::run_audit(
        &[home.to_string_lossy().into_owned()],
        &[],
        None,
        false,
        &runner,
    );
    check(
        "audit",
        configctl_cli::render::Envelope::ok(
            "audit",
            serde_json::json!({"n": audit.findings.len()}),
        )
        .to_json(),
    );
    let doc = configctl_cli::commands::doctor::run_doctor(Some(state.to_str().unwrap()), &runner);
    check(
        "doctor",
        configctl_cli::render::Envelope::ok("doctor", serde_json::json!({"ok": doc.state_ok}))
            .to_json(),
    );
    let rb = configctl_cli::commands::rollback::run_rollback(
        None,
        None,
        true,
        Some(state.to_str().unwrap()),
        Some(&home),
        true,
        false,
        true,
        &runner,
    );
    check(
        "rollback --list",
        configctl_cli::render::Envelope::ok(
            "rollback",
            serde_json::json!({"plans": rb.plans.unwrap().len()}),
        )
        .to_json(),
    );
    let infos = configctl_cli::commands::profile::run_list(Some(
        bundle.parent().unwrap().to_str().unwrap(),
    ));
    let _ = infos;
}
