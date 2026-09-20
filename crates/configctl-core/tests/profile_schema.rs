//! v1.1 profile schema tests: v1 compatibility, migration, v2 round-trip.

use configctl_core::profile::{
    is_supported_schema_version, Profile, SCHEMA_VERSION, SCHEMA_VERSION_V1,
};

const V1_PROFILE: &str = r#"
schema_version = 1
name = "legacy"

[packages]
apt = ["git", "curl"]

[[projects]]
name = "a"
path = "~/a"
vcs = "git"
ecosystems = ["rust"]
env_files = [".env"]
config_files = ["Cargo.toml"]

[[services]]
name = "syncthing.service"
enabled = true
"#;

#[test]
fn v1_profile_parses_and_validates() {
    let p = Profile::from_toml(V1_PROFILE).expect("v1 must parse");
    assert_eq!(p.schema_version, 1);
    assert!(p.validate().is_empty());
    // v2 sections default to absent/empty — never invented.
    assert!(p.machine.is_none());
    assert!(p.hardware.is_none());
    assert!(p.toolchains.is_empty());
    assert!(p.directories.is_empty());
    assert!(p.mounts.is_empty());
    assert!(p.executables.is_empty());
    assert!(p.provenance.is_none());
}

#[test]
fn supported_versions_are_exactly_1_and_2() {
    assert!(is_supported_schema_version(SCHEMA_VERSION_V1));
    assert!(is_supported_schema_version(SCHEMA_VERSION));
    assert!(!is_supported_schema_version(0));
    assert!(!is_supported_schema_version(3));
    assert!(!is_supported_schema_version(99));
}

#[test]
fn migrate_v1_to_v2_preserves_content() {
    let mut p = Profile::from_toml(V1_PROFILE).expect("v1 must parse");
    let migrated = configctl_core::profile_migrate::migrate_to_v2(&mut p).expect("migration works");
    assert!(migrated);
    assert_eq!(p.schema_version, SCHEMA_VERSION);
    assert_eq!(p.provenance.as_ref().and_then(|x| x.migrated_from), Some(1));
    assert!(p.validate().is_empty());
    // Content untouched.
    assert_eq!(p.packages.apt, vec!["git".to_string(), "curl".to_string()]);
    assert_eq!(p.projects.len(), 1);
    // Second call is a no-op.
    let again = configctl_core::profile_migrate::migrate_to_v2(&mut p).expect("idempotent");
    assert!(!again);
}

#[test]
fn migrate_rejects_unknown_versions() {
    let mut p = Profile::new("x");
    p.schema_version = 99;
    assert!(configctl_core::profile_migrate::migrate_to_v2(&mut p).is_err());
}

#[test]
fn v2_full_profile_round_trips() {
    let mut p = Profile::new("full");
    p.machine = Some(configctl_core::profile::MachineSection {
        hostname: None,
        kernel: Some("6.8.0".into()),
        boot_mode: Some("uefi".into()),
        root_filesystem: Some("ext4".into()),
    });
    p.hardware = Some(configctl_core::profile::HardwareSection {
        cpu_model: Some("AMD Ryzen".into()),
        logical_cpus: Some(16),
        total_ram_kib: Some(32 * 1024 * 1024),
        gpus: vec!["0000:01:00.0 10de:2b85".into()],
        cuda: Some(true),
        rocm: Some(false),
        compilers: vec!["gcc (12.3.0)".into()],
    });
    p.packages
        .other
        .insert("cargo".into(), vec!["ripgrep".into(), "bat".into()]);
    p.toolchains.push(configctl_core::profile::ToolchainEntry {
        name: "rustc".into(),
        version: Some("1.97.1".into()),
        provenance: Some("rustup".into()),
    });
    p.directories.push(configctl_core::profile::DirectoryEntry {
        path: "~/projects/a".into(),
        kind: "project".into(),
        classification: None,
    });
    p.files.push(configctl_core::profile::FileEntry {
        target: "~/.gitconfig".into(),
        source: "files/gitconfig".into(),
        mode: Some("0644".into()),
        origin: Some("home".into()),
        detected_by: Some("filesystem.discovery".into()),
        classification: Some("portable".into()),
    });
    p.services.push(configctl_core::profile::ServiceEntry {
        name: "syncthing.service".into(),
        enabled: Some(true),
        running: None,
        scope: Some("user".into()),
        classification: Some("reproducible".into()),
    });
    p.mounts.push(configctl_core::profile::MountEntry {
        mountpoint: "/home".into(),
        fstype: "ext4".into(),
        remote: false,
        pseudo: false,
    });
    p.executables
        .push(configctl_core::profile::ExecutableEntry {
            name: "rg".into(),
            provenance: "cargo".into(),
            version: Some("14.1.0".into()),
        });
    p.projects.push(configctl_core::profile::ProjectEntry {
        name: "a".into(),
        path: "~/projects/a".into(),
        vcs: Some("git".into()),
        ecosystems: vec!["rust".into()],
        env_schema: None,
        env_files: vec![],
        config_files: vec!["Cargo.toml".into()],
        markers: vec!["Cargo.toml".into(), ".git".into()],
        roles: [("source".to_string(), 42)].into_iter().collect(),
    });
    assert!(p.validate().is_empty());
    let toml = p.to_toml().expect("serialize");
    let back = Profile::from_toml(&toml).expect("deserialize");
    assert_eq!(back, {
        let mut c = p.clone();
        c.canonicalize();
        c
    });
}

#[test]
fn v2_rejects_bad_sections() {
    let mut p = Profile::new("bad");
    p.services.push(configctl_core::profile::ServiceEntry {
        name: "evil.txt".into(),
        enabled: None,
        running: None,
        scope: None,
        classification: None,
    });
    assert!(!p.validate().is_empty());
    let mut p2 = Profile::new("bad2");
    p2.directories
        .push(configctl_core::profile::DirectoryEntry {
            path: "~/x".into(),
            kind: "symlink-farm".into(),
            classification: None,
        });
    assert!(!p2.validate().is_empty());
}
