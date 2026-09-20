//! P3 tests: multi-manager package parsing + toolchain discovery.

use configctl_core::command::{CommandOutput, FakeCommandRunner};
use configctl_core::governor::{GovernorBudgets, ResourceGovernor};
use configctl_discovery::packages::collect_packages;
use configctl_discovery::toolchain::{discover_executables_in, probe_version};
use std::sync::Arc;

fn ok(stdout: &str) -> CommandOutput {
    CommandOutput {
        status: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    }
}

fn governor() -> Arc<ResourceGovernor> {
    ResourceGovernor::new(GovernorBudgets::default())
}

#[test]
fn apt_and_cargo_managers_parse_with_provenance() {
    let runner = FakeCommandRunner::new();
    // Probe order: apt, snap, flatpak, cargo, rustup, npm, pip, pipx, uv, mise, asdf.
    runner.queue(ok("git\t1:2.43.0-1ubuntu1\tamd64\nripgrep\t14.1.0-1\tamd64\n"));
    runner.queue(CommandOutput::default()); // snap missing
    runner.queue(CommandOutput::default()); // flatpak missing
    runner.queue(ok("ripgrep v14.1.0:\n    rg (executable)\nbat v0.24.0:\n    bat (executable)\n"));
    // The rest get the default (unavailable) output.

    let inv = collect_packages(&governor(), &runner);
    let apt: Vec<_> = inv.packages.iter().filter(|p| p.manager == "apt").collect();
    assert_eq!(apt.len(), 2);
    assert_eq!(apt[0].name, "git");
    assert_eq!(apt[0].version.as_deref(), Some("1:2.43.0-1ubuntu1"));
    assert_eq!(apt[0].arch.as_deref(), Some("amd64"));
    assert_eq!(apt[0].provenance, "dpkg");

    let cargo: Vec<_> = inv.packages.iter().filter(|p| p.manager == "cargo").collect();
    assert_eq!(cargo.len(), 2);
    assert!(cargo.iter().any(|p| p.name == "ripgrep" && p.version.as_deref() == Some("14.1.0")));
    assert!(cargo.iter().all(|p| p.explicit == Some(true)));

    let managers: Vec<&str> = inv.managers.iter().map(|m| m.manager.as_str()).collect();
    assert!(managers.contains(&"apt"));
    assert!(managers.contains(&"mise"));
    assert!(managers.contains(&"asdf"));
    let snap = inv.managers.iter().find(|m| m.manager == "snap").unwrap();
    assert!(!snap.available);
    assert_eq!(inv.total, inv.packages.len());
}

#[test]
fn hostile_manager_output_cannot_inject() {
    let runner = FakeCommandRunner::new();
    runner.queue(ok("good-pkg\t1.0\tamd64\n$(evil)\t1.0\tamd64\n../../etc\t1.0\tamd64\n"));
    let inv = collect_packages(&governor(), &runner);
    let apt: Vec<_> = inv.packages.iter().filter(|p| p.manager == "apt").collect();
    assert_eq!(apt.len(), 1);
    assert_eq!(apt[0].name, "good-pkg");
}

#[test]
fn unknown_provenance_is_explicit() {
    let runner = FakeCommandRunner::new();
    runner.queue(CommandOutput::default()); // apt missing
    runner.queue(ok("Name  Version  Rev  Tracking  Publisher  Notes\ncode 1.2.3 100 stable vscode classic\n"));
    let inv = collect_packages(&governor(), &runner);
    let snap: Vec<_> = inv.packages.iter().filter(|p| p.manager == "snap").collect();
    assert_eq!(snap.len(), 1);
    assert!(!snap[0].provenance.is_empty());
}

#[test]
fn toolchain_discovers_executables_with_provenance() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("my-tool-xyz");
    std::fs::write(&exe, b"#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.path().join("README.md"), b"docs").unwrap();

    let runner = FakeCommandRunner::new();
    let inv = discover_executables_in(&governor(), &runner, &[dir.path().to_path_buf()]);
    assert_eq!(inv.total, 1);
    assert_eq!(inv.executables[0].name, "my-tool-xyz");
    // Unlisted binaries are never executed: no version probe ran.
    assert!(inv.executables[0].version.is_none());
    assert_eq!(inv.executables[0].provenance, "unknown");
    assert!(runner.recorded().is_empty());
}

#[test]
fn version_probe_only_runs_for_registry_names() {
    let runner = FakeCommandRunner::new();
    runner.queue(ok("cargo 1.97.1 (8bab26f4f 2026-07-14)\n"));
    let gov = governor();
    let v = probe_version(&gov, &runner, std::path::Path::new("/usr/bin/cargo"), "cargo");
    assert_eq!(v.as_deref(), Some("cargo 1.97.1 (8bab26f4f 2026-07-14)"));

    // Unlisted binary: no subprocess, even though a binary exists there.
    let v2 = probe_version(
        &gov,
        &runner,
        std::path::Path::new("/usr/bin/mystery"),
        "mystery",
    );
    assert!(v2.is_none());
    assert_eq!(runner.recorded().len(), 1);
}
