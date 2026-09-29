//! v1.1 hardcore capture + apply policy tests.

use configctl_core::capture::scan_view as stub;
use configctl_core::command::FakeCommandRunner;

// --- Capture: global env, services, lock versions --------------------------

fn v11_view() -> stub::ScanView {
    stub::ScanView {
        projects: vec![],
        env_files: vec![],
        config_files: vec![],
        distro: Some("ubuntu noble".into()),
        excluded_paths: 0,
        warnings: vec![],
        machine: Some(stub::MachineView {
            hostname: None,
            kernel: Some("6.8.0".into()),
            boot_mode: Some("uefi".into()),
            root_filesystem: Some("ext4".into()),
        }),
        hardware: Some(stub::HardwareView {
            cpu_model: Some("AMD".into()),
            logical_cpus: Some(8),
            total_ram_kib: Some(16000000),
            gpus: vec![],
            cuda: Some(false),
            rocm: Some(false),
            compilers: vec!["gcc (12.3.0)".into()],
        }),
        packages_other: vec![("cargo".into(), "ripgrep".into())],
        toolchains: vec![stub::ToolchainView {
            name: "cargo".into(),
            version: Some("1.97.1".into()),
            provenance: "rustup".into(),
        }],
        mounts: vec![stub::MountView {
            mountpoint: "/home".into(),
            fstype: "ext4".into(),
            remote: false,
            pseudo: false,
        }],
        executables: vec![],
        project_detail: Default::default(),
        services: vec![
            stub::ServiceView {
                name: "syncthing.service".into(),
                scope: "user".into(),
                enabled: Some(true),
                active: Some("active/running".into()),
            },
            stub::ServiceView {
                name: "docker.service".into(),
                scope: "system".into(),
                enabled: Some(true),
                active: Some("active/running".into()),
            },
        ],
        global_env: vec![
            stub::GlobalEnvView {
                name: "MYAPP_TOKEN".into(),
                classification: "secret".into(),
                value: None,
            },
            stub::GlobalEnvView {
                name: "EDITOR".into(),
                classification: "public_config".into(),
                value: Some("vim".into()),
            },
            stub::GlobalEnvView {
                name: "MYSTERY_VAR".into(),
                classification: "unknown".into(),
                value: None,
            },
        ],
        package_versions: vec![
            stub::PackageVersionView {
                manager: "cargo".into(),
                name: "ripgrep".into(),
                version: Some("14.1.0".into()),
            },
            stub::PackageVersionView {
                manager: "npm".into(),
                name: "pnpm".into(),
                version: Some("9.0.0".into()),
            },
        ],
    }
}

fn capture_opts() -> configctl_core::capture::CaptureOptions {
    configctl_core::capture::CaptureOptions {
        profile_name: "v11".into(),
        description: None,
        scan_roots: vec![],
        home: None,
        limits: Default::default(),
    }
}

#[test]
fn v11_capture_emits_services_env_lock() {
    let fake = FakeCommandRunner::new();
    let view = v11_view();
    let result =
        configctl_core::capture::run_capture(&capture_opts(), &view, &fake, &[]).expect("capture");
    let p = &result.profile;
    assert_eq!(p.schema_version, configctl_core::profile::SCHEMA_VERSION);

    // Services: user reproduced, system privileged — both explicit.
    assert_eq!(p.services.len(), 2);
    let user = p
        .services
        .iter()
        .find(|s| s.name == "syncthing.service")
        .unwrap();
    assert_eq!(user.scope.as_deref(), Some("user"));
    let system = p
        .services
        .iter()
        .find(|s| s.name == "docker.service")
        .unwrap();
    assert_eq!(system.scope.as_deref(), Some("system"));
    assert_eq!(system.classification.as_deref(), Some("privileged"));

    // Global env: literal captured, secret referenced, unknown recorded.
    let env = p.environment.as_ref().expect("environment emitted");
    assert!(matches!(
        env.get("EDITOR"),
        Some(configctl_core::profile::EnvLiteral::Value(v)) if v == "vim"
    ));
    let secret_lit = env.get("MYAPP_TOKEN").expect("secret ref emitted");
    match secret_lit {
        configctl_core::profile::EnvLiteral::Secret { secret, .. } => {
            assert!(secret.starts_with("secret://v11/global/MYAPP_TOKEN"));
        }
        _ => panic!("expected secret reference"),
    }
    assert!(!env.contains_key("MYSTERY_VAR"));
    assert!(result
        .summary
        .unknown
        .iter()
        .any(|u| u.contains("MYSTERY_VAR")));
    // Manifest carries the global secret (project None, source environment).
    let entry = result
        .manifest
        .secrets
        .iter()
        .find(|s| s.name == "MYAPP_TOKEN")
        .expect("manifest entry");
    assert_eq!(entry.project, None);
    assert_eq!(entry.source, "environment");

    // Lock records other-manager versions; profile names them.
    assert_eq!(
        result
            .lock
            .other
            .get("cargo")
            .and_then(|m| m.get("ripgrep"))
            .map(|s| s.as_str()),
        Some("14.1.0")
    );
    assert!(p
        .packages
        .other
        .get("cargo")
        .map(|v| v.contains(&"ripgrep".to_string()))
        .unwrap_or(false));

    // Machine + hardware + mounts + toolchains present.
    assert_eq!(
        p.machine
            .as_ref()
            .and_then(|m| m.boot_mode.clone())
            .as_deref(),
        Some("uefi")
    );
    assert_eq!(p.mounts.len(), 1);
    assert_eq!(p.toolchains.len(), 1);
    assert!(
        result
            .summary
            .capture_actions
            .get("capture")
            .copied()
            .unwrap_or(0)
            >= 1
    );
    assert!(
        result
            .summary
            .capture_actions
            .get("reference")
            .copied()
            .unwrap_or(0)
            >= 1
    );
    assert!(p.validate().is_empty());
    assert!(result.manifest.validate().is_empty());
}

// --- Plan classes + apply refusal ------------------------------------------

#[test]
fn system_service_ops_are_privileged_user_ops_safe() {
    use configctl_core::observe::{ObservedState, ServiceObs};
    use configctl_core::plan;
    use configctl_core::profile::{Profile, ServiceEntry};
    use std::collections::{BTreeMap, BTreeSet};

    let mut p = Profile::new("svc");
    p.services = vec![
        ServiceEntry {
            name: "app.service".into(),
            enabled: Some(true),
            running: None,
            scope: Some("user".into()),
            classification: None,
        },
        ServiceEntry {
            name: "db.service".into(),
            enabled: Some(true),
            running: None,
            scope: Some("system".into()),
            classification: None,
        },
    ];
    let mut st = ObservedState::default();
    for name in ["app.service", "db.service"] {
        st.services.insert(
            name.into(),
            ServiceObs {
                exists: true,
                enabled: Some(false),
                running: None,
                unknown: false,
            },
        );
    }
    let profile_hash = configctl_core::profile_load::compute_profile_hash(
        &p,
        &None,
        &BTreeMap::new(),
        &BTreeMap::new(),
    );
    let loaded = configctl_core::profile_load::LoadedProfile {
        dir: std::path::PathBuf::from("/tmp/fake"),
        identity: p.name.clone(),
        profile: p,
        manifest: None,
        lock: None,
        env_schemas: BTreeMap::new(),
        payload_hashes: BTreeMap::new(),
        profile_hash,
    };
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "p1", 1000);
    let app = plan
        .operations
        .iter()
        .find(|o| o.target == "app.service")
        .expect("user op");
    assert_eq!(
        app.action_class,
        configctl_core::classify::PlanActionClass::SafeReproduce
    );
    let db = plan
        .operations
        .iter()
        .find(|o| o.target == "db.service")
        .expect("system op");
    assert_eq!(
        db.action_class,
        configctl_core::classify::PlanActionClass::Privileged
    );
    // Plan hash covers classes (stable across identical builds).
    let plan2 = plan::build_plan(&loaded, &st, &BTreeSet::new(), "p1", 1000);
    assert_eq!(plan.plan_hash, plan2.plan_hash);
}

#[test]
fn refusal_rules_block_dangerous_classes_only() {
    use configctl_core::apply::refusal_for_class;
    use configctl_core::classify::PlanActionClass;
    assert!(refusal_for_class(PlanActionClass::SafeReproduce).is_none());
    assert!(refusal_for_class(PlanActionClass::SecretRequired).is_none());
    assert!(refusal_for_class(PlanActionClass::Manual).is_none());
    assert!(refusal_for_class(PlanActionClass::MachineSpecific).is_none());
    assert!(refusal_for_class(PlanActionClass::Privileged).is_some());
    assert!(refusal_for_class(PlanActionClass::Destructive).is_some());
    assert!(refusal_for_class(PlanActionClass::Unsupported).is_some());
}
