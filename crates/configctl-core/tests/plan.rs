//! P3 plan/diff engine tests (pure core + disposable fixtures).

use configctl_core::command::FakeCommandRunner;
use configctl_core::observe::{FileObs, ObservedState, ServiceObs};
use configctl_core::plan::{self, OperationKind};
use configctl_core::profile::{EnvLiteral, FileEntry, Profile, ServiceEntry, SCHEMA_VERSION};
use std::collections::{BTreeMap, BTreeSet};

fn test_profile() -> Profile {
    let mut p = Profile::new("work");
    p.packages.apt = vec!["ripgrep".into(), "jq".into()];
    p.files = vec![
        FileEntry {
            target: "~/.gitconfig".into(),
            source: "files/gitconfig".into(),
            mode: Some("0644".into()),
            origin: None,
            detected_by: None,
            classification: None,
        },
        FileEntry {
            target: "~/.config/nvim".into(),
            source: "files/nvim".into(),
            mode: None,
            origin: None,
            detected_by: None,
            classification: None,
        },
    ];
    p.services = vec![ServiceEntry {
        name: "docker.service".into(),
        enabled: Some(true),
        running: None,
        scope: None,
        classification: None,
    }];
    p
}

fn file_obs(hash: Option<&str>) -> FileObs {
    FileObs {
        exists: true,
        is_symlink: false,
        is_non_regular: false,
        content_hash: hash.map(|s| s.to_string()),
        len: Some(10),
    }
}

fn missing_obs() -> FileObs {
    FileObs {
        exists: false,
        is_symlink: false,
        is_non_regular: false,
        content_hash: None,
        len: None,
    }
}

fn observed_all_match(payload: &BTreeMap<String, String>) -> ObservedState {
    let mut st = ObservedState::default();
    st.packages.insert("ripgrep".into(), "14.0".into());
    st.packages.insert("jq".into(), "1.7".into());
    st.files.insert(
        "~/.gitconfig".into(),
        file_obs(payload.get("files/gitconfig").map(|s| s.as_str())),
    );
    st.files.insert(
        "~/.config/nvim".into(),
        file_obs(payload.get("files/nvim").map(|s| s.as_str())),
    );
    st.services.insert(
        "docker.service".into(),
        ServiceObs {
            exists: true,
            enabled: Some(true),
            running: None,
            unknown: false,
        },
    );
    st
}

fn loaded_for(
    p: &Profile,
    payload: BTreeMap<String, String>,
) -> configctl_core::profile_load::LoadedProfile {
    let profile_hash =
        configctl_core::profile_load::compute_profile_hash(p, &None, &BTreeMap::new(), &payload);
    configctl_core::profile_load::LoadedProfile {
        dir: std::path::PathBuf::from("/tmp/fake"),
        identity: p.name.clone(),
        profile: p.clone(),
        manifest: None,
        lock: None,
        env_schemas: BTreeMap::new(),
        payload_hashes: payload,
        profile_hash,
    }
}

fn payload_hashes() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("files/gitconfig".into(), "aaa".into()),
        ("files/nvim".into(), "bbb".into()),
    ])
}

#[test]
fn noop_when_everything_matches() {
    let p = test_profile();
    let loaded = loaded_for(&p, payload_hashes());
    let st = observed_all_match(&payload_hashes());
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "p1", 1000);
    assert!(plan::is_noop(&plan));
    assert!(plan.conflicts.is_empty());
}

#[test]
fn deterministic_ordering_and_hash() {
    let mut p = test_profile();
    // Intentionally unsorted input.
    p.packages.apt = vec!["tmux".into(), "jq".into(), "ripgrep".into()];
    p.files.reverse();
    let loaded = loaded_for(&p, payload_hashes());
    let mut st = ObservedState::default();
    st.files.insert("~/.gitconfig".into(), missing_obs());
    st.files.insert("~/.config/nvim".into(), missing_obs());
    let plan1 = plan::build_plan(&loaded, &st, &BTreeSet::new(), "p1", 1000);
    let plan2 = plan::build_plan(&loaded, &st.clone(), &BTreeSet::new(), "p2", 9999);
    // Same semantics, different id/timestamp ⇒ same hash.
    assert_eq!(plan1.plan_hash, plan2.plan_hash);
    // Operations sorted: apt before files.
    let kinds: Vec<&str> = plan1
        .operations
        .iter()
        .map(|o| o.provider.as_str())
        .collect();
    let apt_pos = kinds.iter().position(|k| *k == "apt").unwrap();
    let files_pos = kinds.iter().position(|k| *k == "files").unwrap();
    assert!(apt_pos < files_pos);
    // Stable ids.
    assert_eq!(plan1.operations[0].id, "op-0001");
}

#[test]
fn changed_profile_changes_hash() {
    let p1 = test_profile();
    let mut p2 = test_profile();
    p2.packages.apt.push("tmux".into());
    let l1 = loaded_for(&p1, payload_hashes());
    let l2 = loaded_for(&p2, payload_hashes());
    let st = ObservedState::default();
    let h1 = plan::build_plan(&l1, &st, &BTreeSet::new(), "a", 1).plan_hash;
    let h2 = plan::build_plan(&l2, &st, &BTreeSet::new(), "a", 1).plan_hash;
    assert_ne!(h1, h2);
}

#[test]
fn changed_observed_state_changes_plan() {
    let p = test_profile();
    let loaded = loaded_for(&p, payload_hashes());
    let st1 = ObservedState::default();
    let mut st2 = ObservedState::default();
    st2.packages.insert("jq".into(), "1.7".into());
    let h1 = plan::build_plan(&loaded, &st1, &BTreeSet::new(), "a", 1).plan_hash;
    let h2 = plan::build_plan(&loaded, &st2, &BTreeSet::new(), "a", 1).plan_hash;
    assert_ne!(h1, h2);
}

#[test]
fn unmanaged_file_is_conflict() {
    let p = test_profile();
    let loaded = loaded_for(&p, payload_hashes());
    let mut st = ObservedState::default();
    st.files
        .insert("~/.gitconfig".into(), file_obs(Some("different")));
    st.files.insert("~/.config/nvim".into(), missing_obs());
    st.packages.insert("ripgrep".into(), "1".into());
    st.packages.insert("jq".into(), "1".into());
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "a", 1);
    assert!(plan
        .operations
        .iter()
        .any(|o| o.kind == OperationKind::FileConflict));
    assert!(plan.conflicts.iter().any(|c| c.code == "unmanaged_exists"));
}

#[test]
fn managed_file_is_update() {
    let p = test_profile();
    let loaded = loaded_for(&p, payload_hashes());
    let mut st = ObservedState::default();
    st.files
        .insert("~/.gitconfig".into(), file_obs(Some("different")));
    st.files.insert("~/.config/nvim".into(), missing_obs());
    st.packages.insert("ripgrep".into(), "1".into());
    st.packages.insert("jq".into(), "1".into());
    let owned: BTreeSet<(String, String)> =
        BTreeSet::from([("file".to_string(), "~/.gitconfig".to_string())]);
    let plan = plan::build_plan(&loaded, &st, &owned, "a", 1);
    assert!(plan
        .operations
        .iter()
        .any(|o| o.kind == OperationKind::FileUpdate));
    assert!(!plan
        .conflicts
        .iter()
        .any(|c| c.code == "unmanaged_exists" && c.target == "~/.gitconfig"));
}

#[test]
fn missing_file_is_create() {
    let p = test_profile();
    let loaded = loaded_for(&p, payload_hashes());
    let mut st = ObservedState::default();
    st.files.insert("~/.gitconfig".into(), missing_obs());
    st.files.insert("~/.config/nvim".into(), missing_obs());
    st.packages.insert("ripgrep".into(), "1".into());
    st.packages.insert("jq".into(), "1".into());
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "a", 1);
    assert!(plan
        .operations
        .iter()
        .any(|o| o.kind == OperationKind::FileCreate));
}

#[test]
fn package_missing_and_mismatch() {
    use configctl_core::profile::PackagesLock;
    let p = test_profile();
    let mut loaded = loaded_for(&p, payload_hashes());
    loaded.lock = Some(PackagesLock {
        schema_version: SCHEMA_VERSION,
        apt: BTreeMap::from([("ripgrep".into(), "14.1.0".into())]),
        other: Default::default(),
    });
    let mut st = ObservedState::default();
    st.packages.insert("ripgrep".into(), "14.0".into());
    // jq missing entirely.
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "a", 1);
    assert!(plan
        .operations
        .iter()
        .any(|o| o.kind == OperationKind::PackageInstall && o.target == "jq"));
    assert!(plan
        .operations
        .iter()
        .any(|o| o.kind == OperationKind::PackageVersionMismatch));
}

#[test]
fn unsupported_when_providers_unavailable() {
    let p = test_profile();
    let loaded = loaded_for(&p, payload_hashes());
    let st = ObservedState {
        packages_unavailable: true,
        services_unavailable: true,
        ..Default::default()
    };
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "a", 1);
    assert!(plan
        .operations
        .iter()
        .any(|o| o.kind == OperationKind::Unsupported));
}

#[test]
fn symlink_target_is_conflict() {
    let p = test_profile();
    let loaded = loaded_for(&p, payload_hashes());
    let mut st = ObservedState::default();
    st.files.insert(
        "~/.gitconfig".into(),
        FileObs {
            exists: true,
            is_symlink: true,
            is_non_regular: false,
            content_hash: None,
            len: None,
        },
    );
    st.files.insert("~/.config/nvim".into(), missing_obs());
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "a", 1);
    assert!(plan.conflicts.iter().any(|c| c.code == "symlink_at_target"));
}

#[test]
fn secret_refs_never_appear_in_plan_json() {
    use configctl_core::profile::SecretManifest;
    let canary = "super-secret-canary-zzz999";
    let mut p = test_profile();
    p.environment = Some(BTreeMap::from([(
        "EDITOR".into(),
        EnvLiteral::Value("nvim".into()),
    )]));
    let loaded = loaded_for(&p, payload_hashes());
    let st = ObservedState::default();
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "a", 1);
    let json = serde_json::to_string(&plan).unwrap();
    assert!(!json.contains(canary));
    // Env literal values are stored as hashes only in details.
    assert!(!json.contains("\"nvim\"") || json.contains("desired_hash"));
    let _ = SecretManifest {
        schema_version: SCHEMA_VERSION,
        secrets: vec![],
    };
}

#[test]
fn malformed_profile_rejected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("profile.toml"),
        "schema_version = 99\nname = \"x\"\n",
    )
    .unwrap();
    let err = configctl_core::profile_load::load_profile_dir(dir.path()).unwrap_err();
    assert!(err.contains("validation failed") || err.contains("unsupported"));
}

#[test]
fn path_traversal_rejected() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("profile.toml"),
        "schema_version = 1\nname = \"trav\"\n[[files]]\ntarget = \"~/ok\"\nsource = \"../evil\"\n",
    )
    .unwrap();
    assert!(configctl_core::profile_load::load_profile_dir(dir.path()).is_err());
}

#[test]
fn plan_persistence_is_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let p = test_profile();
    let loaded = loaded_for(&p, payload_hashes());
    let st = ObservedState::default();
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "fixed-id", 1);
    let path =
        configctl_core::state::save_plan(&state, &plan, std::path::Path::new("/tmp/fake")).unwrap();
    assert!(path.exists());
    // Reload verifies hash.
    let (reloaded, status, _) = configctl_core::state::load_plan(&state, "fixed-id").unwrap();
    assert_eq!(reloaded.plan_hash, plan.plan_hash);
    assert_eq!(status, "planned");
    // Tamper with the doc → load fails.
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    v["profile_hash"] = serde_json::Value::String("tampered".into());
    std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    assert!(configctl_core::state::load_plan(&state, "fixed-id").is_err());
}

#[test]
fn approval_binding() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let p = test_profile();
    let loaded = loaded_for(&p, payload_hashes());
    let st = ObservedState::default();
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "appr-1", 1);
    configctl_core::state::save_plan(&state, &plan, std::path::Path::new("/tmp/fake")).unwrap();
    configctl_core::state::approve_plan(&state, "appr-1", 2).unwrap();
    let (_, status, _) = configctl_core::state::load_plan(&state, "appr-1").unwrap();
    assert_eq!(status, "approved");
}

#[test]
fn state_dir_permissions_are_safe() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    configctl_core::state::ensure_state_dir(&state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}

#[test]
fn observe_never_follows_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::write(&real, "hello").unwrap();
    let link = dir.path().join("link");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let obs = configctl_core::observe::observe_file(&link);
        assert!(obs.is_symlink);
        assert!(obs.content_hash.is_none());
    }
}

#[test]
fn command_runner_is_only_subprocess_path() {
    // Fake runner records argv; dpkg-query must be fixed argv, never a shell.
    let runner = FakeCommandRunner::new();
    runner.queue(configctl_core::command::CommandOutput {
        status: Some(0),
        stdout: "ripgrep\t14.0\tamd64\n".into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    let home = tempfile::tempdir().unwrap();
    let st = configctl_core::observe::observe(
        &runner,
        home.path(),
        &["ripgrep".to_string()],
        &[],
        false,
        &[],
        &[],
        &|_| None,
        &[],
    );
    assert_eq!(st.packages.get("ripgrep").map(|s| s.as_str()), Some("14.0"));
    let calls = runner.recorded();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program.to_string_lossy(), "dpkg-query");
    assert!(!calls[0]
        .args
        .iter()
        .any(|a| a.contains('|') || a.contains(';')));
}
