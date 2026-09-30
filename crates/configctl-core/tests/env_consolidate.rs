//! v1.2 env-consolidation plan builder (pure core, no I/O).

use configctl_core::envmap;
use configctl_core::plan::{self, OperationKind, RcTarget};
use configctl_core::profile::{EnvLiteral, Profile};
use configctl_core::profile_load::LoadedProfile;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn loaded(env: &[(&str, EnvLiteral)]) -> LoadedProfile {
    let mut profile = Profile::new("work");
    let mut map = BTreeMap::new();
    for (k, v) in env {
        map.insert((*k).to_string(), v.clone());
    }
    profile.environment = Some(map);
    LoadedProfile {
        dir: PathBuf::from("/nonexistent-bundle"),
        identity: "work".into(),
        profile,
        manifest: None,
        lock: None,
        env_schemas: BTreeMap::new(),
        payload_hashes: BTreeMap::new(),
        profile_hash: "hash-of-profile".into(),
    }
}

fn literal(v: &str) -> EnvLiteral {
    EnvLiteral::Value(v.to_string())
}

#[test]
fn plan_writes_canonical_file_and_appends_include_blocks() {
    let loaded = loaded(&[("EDITOR", literal("vim")), ("LANG", literal("en_US.UTF-8"))]);
    let bashrc_current = b"export EDITOR=nano\n".to_vec();
    let targets = vec![RcTarget {
        target: "~/.bashrc".into(),
        current: Some(bashrc_current.clone()),
    }];

    let plan = plan::build_env_consolidation_plan(
        &loaded,
        &targets,
        None,
        None,
        Vec::new(),
        "env-1",
        1000,
    );

    let write = plan
        .operations
        .iter()
        .find(|o| o.kind == OperationKind::EnvFileWrite)
        .expect("env file op");
    assert_eq!(write.provider, "envfile");
    assert_eq!(write.target, "~/.config/configctl/env.sh");
    assert_eq!(write.action_class.as_str(), "SAFE_REPRODUCE");
    // File did not exist at plan time.
    assert!(write.expected_before.is_none());
    // The desired hash is the exact file-content identity of the composed file.
    let composed = envmap::canonical_env_file(&[
        ("EDITOR".to_string(), "vim".to_string()),
        ("LANG".to_string(), "en_US.UTF-8".to_string()),
    ]);
    assert_eq!(
        write.desired_after.as_deref(),
        Some(configctl_core::hash::file_content_hash(composed.as_bytes()).as_str())
    );

    let include = plan
        .operations
        .iter()
        .find(|o| o.kind == OperationKind::IncludeLineAdd)
        .expect("include op");
    assert_eq!(include.target, "~/.bashrc");
    // TOCTOU guard is the exact bytes seen at plan time.
    assert_eq!(
        include.expected_before.as_deref(),
        Some(configctl_core::hash::file_content_hash(&bashrc_current).as_str())
    );
    let updated = envmap::ensure_include_block("export EDITOR=nano\n");
    assert_eq!(
        include.desired_after.as_deref(),
        Some(configctl_core::hash::file_content_hash(updated.as_bytes()).as_str())
    );

    assert!(plan.conflicts.is_empty());
    // No values are leaked into summaries or warnings.
    for op in &plan.operations {
        assert!(!op.summary.contains("vim"));
        assert!(!op.summary.contains("en_US.UTF-8"));
    }
}

#[test]
fn secret_entries_never_reach_the_canonical_file() {
    let loaded = loaded(&[
        ("EDITOR", literal("vim")),
        (
            "API_TOKEN",
            EnvLiteral::Secret {
                secret: "secret://api-token".into(),
                required: true,
            },
        ),
    ]);
    let entries = plan::canonical_env_entries(&loaded);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "EDITOR");
    assert!(envmap::first_secret_like(&entries).is_none());

    let plan =
        plan::build_env_consolidation_plan(&loaded, &[], None, None, Vec::new(), "env-2", 1000);
    let composed = envmap::canonical_env_file(&entries);
    assert!(!composed.contains("API_TOKEN"));
    assert!(!composed.contains("secret://"));
    let write = plan
        .operations
        .iter()
        .find(|o| o.kind == OperationKind::EnvFileWrite)
        .unwrap();
    assert!(!write.summary.contains("API_TOKEN"));
}

#[test]
fn secret_like_literal_is_refused_by_the_screen() {
    let entries = vec![("DB_PASSWORD".to_string(), "hunter2".to_string())];
    assert_eq!(
        envmap::first_secret_like(&entries).as_deref(),
        Some("DB_PASSWORD")
    );
}

#[test]
fn files_that_already_have_the_block_are_left_alone() {
    let loaded = loaded(&[("EDITOR", literal("vim"))]);
    let with_block = envmap::ensure_include_block("export EDITOR=nano\n");
    let targets = vec![
        RcTarget {
            target: "~/.bashrc".into(),
            current: Some(with_block.clone().into_bytes()),
        },
        RcTarget {
            target: "~/.zshrc".into(),
            current: Some(b"export EDITOR=emacs\n".to_vec()),
        },
    ];
    let plan = plan::build_env_consolidation_plan(
        &loaded,
        &targets,
        None,
        None,
        Vec::new(),
        "env-3",
        1000,
    );

    let includes: Vec<&str> = plan
        .operations
        .iter()
        .filter(|o| o.kind == OperationKind::IncludeLineAdd)
        .map(|o| o.target.as_str())
        .collect();
    assert_eq!(includes, vec!["~/.zshrc"]);
}

#[test]
fn an_already_current_canonical_file_is_not_rewritten() {
    let loaded = loaded(&[("EDITOR", literal("vim"))]);
    let composed = envmap::canonical_env_file(&[("EDITOR".to_string(), "vim".to_string())]);
    let plan = plan::build_env_consolidation_plan(
        &loaded,
        &[],
        Some(composed.as_bytes()),
        None,
        Vec::new(),
        "env-4",
        1000,
    );
    // The canonical file already holds exactly the desired bytes.
    assert!(
        !plan
            .operations
            .iter()
            .any(|o| o.kind == OperationKind::EnvFileWrite),
        "canonical file must not be rewritten when it already matches"
    );

    // With the session artifact also in sync, the whole plan is a no-op.
    let mut envd = BTreeMap::new();
    envd.insert("EDITOR".to_string(), "vim".to_string());
    let clean = plan::build_env_consolidation_plan(
        &loaded,
        &[],
        Some(composed.as_bytes()),
        Some(&envd),
        Vec::new(),
        "env-4b",
        1000,
    );
    assert!(plan::is_noop(&clean), "expected a no-op plan");
}

#[test]
fn plan_is_deterministic_and_ids_are_stable() {
    let loaded = loaded(&[("EDITOR", literal("vim"))]);
    let targets = vec![
        RcTarget {
            target: "~/.profile".into(),
            current: Some(b"export EDITOR=nano\n".to_vec()),
        },
        RcTarget {
            target: "~/.bashrc".into(),
            current: Some(b"export EDITOR=nano\n".to_vec()),
        },
    ];
    let a =
        plan::build_env_consolidation_plan(&loaded, &targets, None, None, Vec::new(), "env-5", 1);
    let b = plan::build_env_consolidation_plan(
        &loaded,
        &targets,
        None,
        None,
        Vec::new(),
        "env-5",
        99999,
    );
    assert_eq!(
        a.plan_hash, b.plan_hash,
        "created_at must not affect the hash"
    );
    assert_eq!(
        a.operations.iter().map(|o| &o.id).collect::<Vec<_>>(),
        b.operations.iter().map(|o| &o.id).collect::<Vec<_>>()
    );
    // Sorted by target: ~/.bashrc before ~/.profile.
    let includes: Vec<&str> = a
        .operations
        .iter()
        .filter(|o| o.kind == OperationKind::IncludeLineAdd)
        .map(|o| o.target.as_str())
        .collect();
    assert_eq!(includes, vec!["~/.bashrc", "~/.profile"]);
}

#[test]
fn empty_environment_is_an_explicit_noop_with_a_warning() {
    let loaded = loaded(&[]);
    let plan =
        plan::build_env_consolidation_plan(&loaded, &[], None, None, Vec::new(), "env-6", 1000);
    assert!(plan::is_noop(&plan));
    assert!(plan.warnings.iter().any(|w| w.code == "no_environment"));
}

#[test]
fn session_artifact_ops_are_emitted_only_while_differing() {
    let loaded = loaded(&[("EDITOR", literal("vim")), ("LANG", literal("en_US.UTF-8"))]);

    // Nothing managed yet: both literals need a session-artifact op.
    let fresh =
        plan::build_env_consolidation_plan(&loaded, &[], None, None, Vec::new(), "env-7", 1);
    let session: Vec<&str> = fresh
        .operations
        .iter()
        .filter(|o| o.kind == OperationKind::EnvironmentSchemaChange)
        .map(|o| o.target.as_str())
        .collect();
    assert_eq!(session, vec!["EDITOR", "LANG"]);
    let editor = fresh
        .operations
        .iter()
        .find(|o| o.target == "EDITOR" && o.kind == OperationKind::EnvironmentSchemaChange)
        .unwrap();
    assert_eq!(editor.provider, "env");
    assert!(editor.expected_before.is_none());
    assert_eq!(
        editor.desired_after.as_deref(),
        Some(configctl_core::hash::env_value_hash("vim").as_str())
    );
    assert_eq!(
        editor.details.get("variable").map(String::as_str),
        Some("EDITOR")
    );

    // EDITOR already matches, LANG does not: only LANG is planned.
    let mut current = BTreeMap::new();
    current.insert("EDITOR".to_string(), "vim".to_string());
    let partial = plan::build_env_consolidation_plan(
        &loaded,
        &[],
        None,
        Some(&current),
        Vec::new(),
        "env-8",
        1,
    );
    let session: Vec<&str> = partial
        .operations
        .iter()
        .filter(|o| o.kind == OperationKind::EnvironmentSchemaChange)
        .map(|o| o.target.as_str())
        .collect();
    assert_eq!(session, vec!["LANG"]);
    let lang = partial
        .operations
        .iter()
        .find(|o| o.target == "LANG")
        .unwrap();
    assert_eq!(lang.expected_before, None, "LANG was not set before");
}
