//! v1.1 classification model tests: unknown → classify → preserve.

use configctl_core::classify::{
    CaptureAction, EnvClass, FileKind, PlanActionClass, Reproducibility, ResourceClass,
    classify_env_var, classify_file, plan_class_for,
};
use std::path::Path;

fn classify(name: &str) -> configctl_core::classify::Classification {
    classify_file(Path::new(name), FileKind::Regular, false)
}

#[test]
fn secret_filenames_are_reference_only() {
    for name in [
        "/home/u/.ssh/id_ed25519",
        "/home/u/.ssh/id_rsa",
        "/home/u/.gnupg/secring.gpg",
        "/home/u/x.pem",
        "/home/u/srv.key",
        "/home/u/.env",
    ] {
        let c = classify(name);
        assert!(
            matches!(
                c.class,
                ResourceClass::Secret | ResourceClass::Credential
            ),
            "{name}: {:?}",
            c.class
        );
        assert_eq!(c.action, CaptureAction::Reference);
        assert_eq!(c.reproducibility, Reproducibility::Reference);
        assert!(!c.reason.is_empty());
        assert!(!c.signals.is_empty());
    }
}

#[test]
fn public_keys_are_capturable() {
    let c = classify("/home/u/.ssh/id_ed25519.pub");
    assert_eq!(c.class, ResourceClass::Credential);
    assert_eq!(c.action, CaptureAction::Capture);
}

#[test]
fn generated_and_cache_dirs_are_excluded_with_reason() {
    for (path, class) in [
        ("/home/u/proj/target/debug/app", ResourceClass::Generated),
        ("/home/u/proj/node_modules/react/index.js", ResourceClass::Generated),
        ("/home/u/proj/dist/bundle.js", ResourceClass::Generated),
        ("/home/u/.cache/mozilla/x", ResourceClass::Cache),
        ("/home/u/proj/__pycache__/a.pyc", ResourceClass::Generated),
    ] {
        let c = classify(path);
        assert_eq!(c.class, class, "{path}");
        assert_eq!(c.action, CaptureAction::Exclude);
        assert!(!c.reason.is_empty());
    }
}

#[test]
fn vcs_metadata_is_observed_for_provenance() {
    let c = classify("/home/u/proj/.git/objects/ab/cd");
    assert_eq!(c.class, ResourceClass::Dependency);
    assert_eq!(c.action, CaptureAction::Observe);
}

#[test]
fn lockfiles_are_reproducible_and_captured() {
    for name in ["Cargo.lock", "package-lock.json", "go.sum", "uv.lock"] {
        let c = classify(&format!("/home/u/proj/{name}"));
        assert_eq!(c.class, ResourceClass::Reproducible, "{name}");
        assert_eq!(c.action, CaptureAction::Capture, "{name}");
    }
}

#[test]
fn unknown_files_are_preserved_not_dropped() {
    let c = classify("/home/u/.config/someapp/weird-blob.dat");
    assert_eq!(c.class, ResourceClass::Unknown);
    // Unknown is observed with evidence — never silently excluded.
    assert_eq!(c.action, CaptureAction::Observe);
    assert!(c.signals.iter().any(|s| s.contains("extension")));
    assert!(!c.reason.is_empty());
}

#[test]
fn special_files_are_observed_never_read() {
    for kind in [FileKind::Socket, FileKind::Fifo, FileKind::BlockDevice, FileKind::CharDevice] {
        let c = classify_file(Path::new("/dev/x"), kind, false);
        assert_eq!(c.class, ResourceClass::Unsupported);
        assert_eq!(c.action, CaptureAction::Observe);
        assert!(kind.is_special());
    }
}

#[test]
fn executables_reproduce_via_provenance() {
    let c = classify_file(Path::new("/home/u/.cargo/bin/rg"), FileKind::Regular, true);
    assert_eq!(c.class, ResourceClass::Dependency);
    assert_eq!(c.action, CaptureAction::Observe);
}

#[test]
fn every_classification_has_action_and_reason() {
    // Property: no classification may lack a reason.
    let paths = [
        "/home/u/.bashrc",
        "/home/u/.config/nvim/init.lua",
        "/home/u/proj/src/main.rs",
        "/home/u/.ssh/config",
        "/home/u/.aws/config",
        "/etc/hostname",
        "/proc/version",
    ];
    for p in paths {
        let c = classify(p);
        assert!(!c.reason.is_empty(), "{p}");
        assert!(!c.signals.is_empty(), "{p}");
    }
}

#[test]
fn env_var_classification() {
    assert_eq!(classify_env_var("DATABASE_PASSWORD"), EnvClass::Secret);
    assert_eq!(classify_env_var("GITHUB_TOKEN"), EnvClass::Secret);
    assert_eq!(classify_env_var("AWS_SECRET_ACCESS_KEY"), EnvClass::Secret);
    assert_eq!(classify_env_var("PATH"), EnvClass::Path);
    assert_eq!(classify_env_var("HOME"), EnvClass::MachineSpecific);
    assert_eq!(classify_env_var("EDITOR"), EnvClass::PublicConfig);
    assert_eq!(classify_env_var("SHLVL"), EnvClass::Runtime);
    assert_eq!(classify_env_var("SOME_APP_FROBNICATOR"), EnvClass::Unknown);
}

#[test]
fn plan_classes_gate_execution() {
    let secret = classify("/home/u/.ssh/id_rsa");
    assert_eq!(plan_class_for(&secret), PlanActionClass::SecretRequired);
    let gen = classify("/home/u/proj/target/x");
    assert_eq!(plan_class_for(&gen), PlanActionClass::Unsupported);
    let unk = classify("/home/u/.config/mystery/blob");
    assert_eq!(plan_class_for(&unk), PlanActionClass::Manual);
    let lock = classify("/home/u/proj/Cargo.lock");
    assert_eq!(plan_class_for(&lock), PlanActionClass::SafeReproduce);
}
