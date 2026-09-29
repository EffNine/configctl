//! Unit tests for P2 profile model, paths, env schemas, secrets, packages,
//! files, and git metadata.

use configctl_core::capture;
use configctl_core::env_schema::{self, ObservedVar, ObservedVarWithSource};
use configctl_core::files;
use configctl_core::gitmeta;
use configctl_core::packages;
use configctl_core::paths;
use configctl_core::profile::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

// --- Profile serialization ---

#[test]
fn profile_serialization_round_trip() {
    let mut p = Profile::new("my-linux-dev");
    p.description = Some("Captured development environment".into());
    p.platform = Some(Platform {
        os: "linux".into(),
        arch: "x86_64".into(),
        distro: Some("ubuntu noble".into()),
        kernel: None,
    });
    p.packages.apt = vec!["git".into(), "curl".into()];
    p.files.push(FileEntry {
        target: "~/.gitconfig".into(),
        source: "files/home/gitconfig".into(),
        mode: Some("0644".into()),
        origin: None,
        detected_by: None,
        classification: None,
    });
    p.git = Some(GitConfig {
        user_name: Some("Test".into()),
        user_email: Some("test@example.com".into()),
        ..GitConfig::default()
    });
    p.projects.push(ProjectEntry {
        name: "project-a".into(),
        path: "~/projects/project-a".into(),
        vcs: Some("git".into()),
        ecosystems: vec!["rust".into()],
        env_schema: Some("env/project-a.toml".into()),
        env_files: vec![".env".into()],
        config_files: vec!["Cargo.toml".into()],
        markers: vec![],
        roles: Default::default(),
    });
    let toml = p.to_toml().expect("serialize");
    let back = Profile::from_toml(&toml).expect("deserialize");
    let mut p2 = p.clone();
    p2.canonicalize();
    assert_eq!(back, p2);
    assert!(back.validate().is_empty());
}

#[test]
fn profile_rejects_bad_schema_version() {
    let mut p = Profile::new("work");
    p.schema_version = 99;
    assert!(!p.validate().is_empty());
}

#[test]
fn profile_accepts_v1_schema_for_backward_compatibility() {
    let mut p = Profile::new("work");
    p.schema_version = configctl_core::profile::SCHEMA_VERSION_V1;
    assert!(p.validate().is_empty());
}

#[test]
fn profile_rejects_duplicate_targets_and_packages() {
    let mut p = Profile::new("work");
    p.packages.apt = vec!["git".into(), "git".into()];
    p.files.push(FileEntry {
        target: "~/.gitconfig".into(),
        source: "files/a".into(),
        mode: None,
        origin: None,
        detected_by: None,
        classification: None,
    });
    p.files.push(FileEntry {
        target: "~/.gitconfig".into(),
        source: "files/b".into(),
        mode: None,
        origin: None,
        detected_by: None,
        classification: None,
    });
    let errs = p.validate();
    assert!(errs.iter().any(|e| e.contains("duplicate package")));
    assert!(errs.iter().any(|e| e.contains("duplicate file target")));
}

#[test]
fn profile_rejects_traversal_and_absolute_targets() {
    let mut p = Profile::new("work");
    p.files.push(FileEntry {
        target: "../../etc/passwd".into(),
        source: "files/x".into(),
        mode: None,
        origin: None,
        detected_by: None,
        classification: None,
    });
    p.files.push(FileEntry {
        target: "/etc/passwd".into(),
        source: "files/y".into(),
        mode: None,
        origin: None,
        detected_by: None,
        classification: None,
    });
    p.files.push(FileEntry {
        target: "~/.ok".into(),
        source: "../escape".into(),
        mode: None,
        origin: None,
        detected_by: None,
        classification: None,
    });
    let errs = p.validate();
    assert!(errs.len() >= 3, "all bad paths rejected: {errs:?}");
}

#[test]
fn profile_rejects_bad_modes_and_env_names() {
    let mut p = Profile::new("work");
    p.files.push(FileEntry {
        target: "~/.x".into(),
        source: "files/x".into(),
        mode: Some("0999".into()),
        origin: None,
        detected_by: None,
        classification: None,
    });
    let mut env = BTreeMap::new();
    env.insert("1BAD".into(), EnvLiteral::Value("x".into()));
    p.environment = Some(env);
    let errs = p.validate();
    assert!(errs.iter().any(|e| e.contains("mode")));
    assert!(errs.iter().any(|e| e.contains("variable name")));
}

#[test]
fn profile_rejects_secret_like_literals() {
    let mut p = Profile::new("work");
    let mut env = BTreeMap::new();
    env.insert(
        "MY_PASSWORD".into(),
        EnvLiteral::Value("hunter2-secret-value".into()),
    );
    p.environment = Some(env);
    let errs = p.validate();
    assert!(errs.iter().any(|e| e.contains("looks like a secret")));
}

#[test]
fn profile_rejects_unknown_keys() {
    let bad = "schema_version = 1\nname = \"work\"\nbogus_key = 1\n";
    assert!(Profile::from_toml(bad).is_err());
}

// --- Paths ---

#[test]
fn path_validation_matrix() {
    assert!(paths::validate_file_target("~/.gitconfig").is_ok());
    assert!(paths::validate_file_target("/etc/passwd").is_err());
    assert!(paths::validate_file_target("../../etc/passwd").is_err());
    assert!(paths::validate_file_target("~/../escape").is_err());
    assert!(paths::validate_file_target("~/").is_err());
    assert!(paths::validate_bundle_source("files/gitconfig").is_ok());
    assert!(paths::validate_bundle_source("/abs").is_err());
    assert!(paths::validate_bundle_source("../escape").is_err());
    assert!(paths::validate_env_schema_ref("env/foo.toml").is_ok());
    assert!(paths::validate_env_schema_ref("other/foo.toml").is_err());
    assert!(paths::validate_project_path("~/projects/a").is_ok());
    assert!(paths::validate_project_path("/tmp/fixture").is_ok());
    assert!(paths::validate_project_path("../../etc/passwd").is_err());
    assert!(paths::parse_mode("0600").is_ok());
    assert!(paths::parse_mode("0644").is_ok());
    assert!(paths::parse_mode("0999").is_err());
    assert!(paths::validate_env_name("PORT").is_ok());
    assert!(paths::validate_env_name("1BAD").is_err());
    assert!(paths::validate_profile_name("my-linux-dev").is_ok());
    assert!(paths::validate_profile_name("Bad Name!").is_err());
    assert!(paths::validate_package_name("git").is_ok());
    assert!(paths::validate_package_name("git; rm -rf").is_err());
    assert!(paths::validate_secret_ref("secret://work/dev/KEY").is_ok());
    assert!(paths::validate_secret_ref("sk-abcdef").is_err());
}

#[test]
fn portable_conversion() {
    assert_eq!(
        paths::to_portable("/home/alice/projects/a", "/home/alice"),
        "~/projects/a"
    );
    assert_eq!(
        paths::to_portable("/tmp/fixture", "/home/alice"),
        "/tmp/fixture"
    );
}

// --- Env schema ---

#[test]
fn env_schema_defaults_and_secret_evidence() {
    let obs = vec![
        ObservedVar {
            name: "PORT".into(),
            classification: "config".into(),
            from_example: false,
            value: Some("3000".into()),
        },
        ObservedVar {
            name: "OPENAI_API_KEY".into(),
            classification: "likely_secret".into(),
            from_example: true,
            value: Some("sk-test-123".into()),
        },
    ];
    let s = env_schema::build_env_schema("proj", &obs);
    assert!(s.validate().is_empty());
    let port = s.variables.iter().find(|v| v.name == "PORT").unwrap();
    assert_eq!(port.var_type, "integer");
    assert!(!port.secret);
    assert!(!port.required);
    let key = s
        .variables
        .iter()
        .find(|v| v.name == "OPENAI_API_KEY")
        .unwrap();
    assert!(key.secret);
    assert!(key.required);
    // Deterministic ordering.
    let names: Vec<&str> = s.variables.iter().map(|v| v.name.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
    // Round-trip.
    let toml = s.to_toml().unwrap();
    let back = EnvSchema::from_toml(&toml).unwrap();
    assert_eq!(back, s);
}

#[test]
fn env_schema_enum_only_for_known_vars() {
    let obs = vec![ObservedVar {
        name: "NODE_ENV".into(),
        classification: "config".into(),
        from_example: true,
        value: Some("production".into()),
    }];
    let s = env_schema::build_env_schema("proj", &obs);
    let v = &s.variables[0];
    assert_eq!(v.var_type, "enum");
    assert!(s.validate().is_empty());
}

#[test]
fn secret_manifest_dedupes_deterministically() {
    let mut per: BTreeMap<String, Vec<ObservedVarWithSource>> = BTreeMap::new();
    per.insert(
        "proj".into(),
        vec![
            ObservedVarWithSource {
                name: "KEY".into(),
                classification: "likely_secret".into(),
                source: ".env.production".into(),
                from_example: false,
            },
            ObservedVarWithSource {
                name: "KEY".into(),
                classification: "secret".into(),
                source: ".env".into(),
                from_example: false,
            },
            ObservedVarWithSource {
                name: "PORT".into(),
                classification: "config".into(),
                source: ".env".into(),
                from_example: false,
            },
        ],
    );
    let m = env_schema::build_secret_manifest("work", &per);
    assert_eq!(m.secrets.len(), 1);
    assert_eq!(m.secrets[0].source, ".env");
    assert_eq!(m.secrets[0].classification, "secret");
    assert_eq!(m.secrets[0].secret_ref, "secret://work/proj/KEY");
    assert!(m.validate().is_empty());
    let toml = m.to_toml().unwrap();
    assert!(!toml.contains("sk-"));
    let back = SecretManifest::from_toml(&toml).unwrap();
    assert_eq!(back, m);
}

// --- Packages ---

#[test]
fn package_capture_uses_allowlist_policy() {
    use configctl_core::command::{CommandOutput, FakeCommandRunner};
    let fake = FakeCommandRunner::new();
    fake.queue(CommandOutput {
        status: Some(0),
        stdout:
            "git\t1:2.43.0\tamd64\ncurl\t8.5.0\tamd64\nlibc6\t2.39\tamd64\nbad;name\t1.0\tamd64\n"
                .into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    let cap = packages::capture_packages(&fake);
    assert!(!cap.unavailable);
    assert_eq!(cap.installed_total, 3);
    // libc6 excluded by policy; bad name rejected by validation.
    assert_eq!(cap.selected.len(), 2);
    assert!(packages::is_tooling_package("git"));
    assert!(!packages::is_tooling_package("libc6"));
    // Fixed argv, no shell.
    let calls = fake.recorded();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program.to_string_lossy(), "dpkg-query");
    for a in &calls[0].args {
        assert!(!a.contains(';') && !a.contains('|') && !a.contains("$("));
    }
    // Deterministic names.
    let names = packages::apt_names(&cap);
    assert_eq!(names, vec!["curl".to_string(), "git".to_string()]);
}

#[test]
fn package_capture_unavailable_when_dpkg_missing() {
    use configctl_core::command::{CommandOutput, FakeCommandRunner};
    let fake = FakeCommandRunner::new();
    fake.queue(CommandOutput {
        status: Some(1),
        stdout: String::new(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    let cap = packages::capture_packages(&fake);
    assert!(cap.unavailable);
}

// --- Files ---

#[test]
fn file_safety_symlink_oversize_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    // Regular safe file.
    let safe = root.join("safe.conf");
    std::fs::write(&safe, "EDITOR=nvim\n").unwrap();
    assert!(matches!(
        files::decide_file(&safe, std::slice::from_ref(&root), 1024),
        files::FileDecision::Capture
    ));
    // Symlink rejected.
    #[cfg(unix)]
    {
        let target = root.join("real.conf");
        std::fs::write(&target, "x=1\n").unwrap();
        let link = root.join("link.conf");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            files::decide_file(&link, std::slice::from_ref(&root), 1024),
            files::FileDecision::Skip { .. }
        ));
    }
    // Oversized rejected.
    let big = root.join("big.conf");
    std::fs::write(&big, vec![b'x'; 2048]).unwrap();
    assert!(matches!(
        files::decide_file(&big, std::slice::from_ref(&root), 16),
        files::FileDecision::Skip { .. }
    ));
    // Secret-bearing rejected.
    let sec = root.join("sec.conf");
    std::fs::write(&sec, "password = hunter2-secret-value\n").unwrap();
    assert!(matches!(
        files::decide_file(&sec, std::slice::from_ref(&root), 4096),
        files::FileDecision::Skip { .. }
    ));
    // Outside roots rejected.
    let outside = tmp.path().join("outside.conf");
    let other_root = tmp.path().join("other");
    std::fs::create_dir_all(&other_root).unwrap();
    std::fs::write(&outside, "x=1\n").unwrap();
    assert!(matches!(
        files::decide_file(&outside, &[other_root], 4096),
        files::FileDecision::Skip { .. }
    ));
}

#[test]
fn atomic_write_stays_inside_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let bundle = tmp.path().join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    let dest = bundle.join("profile.toml");
    files::atomic_write_inside(&bundle, &dest, b"schema_version = 1\n").unwrap();
    assert!(dest.exists());
    // Escape refused.
    let evil = PathBuf::from("/tmp/evil-capture-test");
    assert!(files::atomic_write_inside(&bundle, &evil, b"x").is_err());
}

// --- Git ---

#[test]
fn git_capture_allowlists_and_denies_creds() {
    use configctl_core::command::{CommandOutput, FakeCommandRunner};
    let fake = FakeCommandRunner::new();
    fake.queue(CommandOutput {
        status: Some(0),
        stdout: "user.name=Test User\nuser.email=test@example.com\ncredential.helper=store\ncredential.store=pure-secret-should-not-appear\nhttp.extraheader=SECRET-TOKEN-VALUE\n alias.co=checkout\ncommit.gpgsign=true\n".into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    let cfg = gitmeta::capture_git(&fake).expect("git available");
    assert_eq!(cfg.user_name.as_deref(), Some("Test User"));
    assert_eq!(cfg.credential_helper.as_deref(), Some("store"));
    assert!(cfg.aliases.contains_key("co"));
    // http header must not be captured anywhere in the struct rendering.
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("SECRET-TOKEN-VALUE"));
}

// --- Capture determinism ---

#[test]
fn capture_ordering_is_deterministic() {
    use configctl_core::capture::scan_view as stub;
    use configctl_core::command::FakeCommandRunner;
    let view = stub::ScanView {
        projects: vec![
            stub::ProjectView {
                path: "/tmp/b".into(),
                name: "b".into(),
                vcs: "git".into(),
                hints: vec!["rust".into()],
            },
            stub::ProjectView {
                path: "/tmp/a".into(),
                name: "a".into(),
                vcs: "git".into(),
                hints: vec![],
            },
        ],
        env_files: vec![],
        config_files: vec![],
        distro: None,
        excluded_paths: 0,
        warnings: vec![],
        machine: None,
        hardware: None,
        packages_other: vec![],
        toolchains: vec![],
        mounts: vec![],
        executables: vec![],
        project_detail: Default::default(),
        services: vec![],
        global_env: vec![],
        package_versions: vec![],
    };
    let mk = || {
        let fake = FakeCommandRunner::new();
        let opts = capture::CaptureOptions {
            profile_name: "work".into(),
            description: None,
            scan_roots: vec![PathBuf::from("/tmp")],
            home: None,
            limits: Default::default(),
        };
        capture::run_capture(&opts, &view, &fake, &[]).unwrap()
    };
    let r1 = mk();
    let r2 = mk();
    // Same inputs → identical profile TOML (timestamps excluded from the
    // comparison: they are informational metadata, not reproducible content).
    let mut p1 = r1.profile.clone();
    let mut p2 = r2.profile.clone();
    p1.metadata = None;
    p2.metadata = None;
    assert_eq!(p1.to_toml().unwrap(), p2.to_toml().unwrap());
}
