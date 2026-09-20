//! Discovery unit tests: project markers, env filenames, secret
//! classification, entropy, config registry, walker limits.

use configctl_core::envfile::parse_env;
use configctl_core::limits::Limits;
use configctl_discovery::config::{match_config_type, CONFIG_TYPES};
use configctl_discovery::env::{env_layer, is_env_filename};
use configctl_discovery::project::detect_project;
use configctl_discovery::secret::{classify_variable, Classification, EntropyScorer, NAME_LEXICON};
use configctl_discovery::walker::{BoundedWalker, WalkRules};

// --- project marker detection --------------------------------------------

#[test]
fn rust_project_detected() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("Cargo.toml"), "[package]\n").unwrap();
    let det = detect_project(tmp.path());
    assert!(det.is_project());
    assert_eq!(det.confidence(), "likely");
    assert!(det.markers_found.iter().any(|m| m == "Cargo.toml"));
}

#[test]
fn git_plus_manifest_is_certain() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join(".git")).unwrap();
    std::fs::write(tmp.path().join("Cargo.toml"), "[package]\n").unwrap();
    let det = detect_project(tmp.path());
    assert!(det.is_project());
    assert_eq!(det.confidence(), "certain");
    assert_eq!(det.vcs, configctl_discovery::project::VcsType::Git);
}

#[test]
fn empty_dir_is_not_a_project() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("README.md"), "hi\n").unwrap();
    let det = detect_project(tmp.path());
    assert!(!det.is_project());
}

#[test]
fn bare_git_dir_flagged_with_warning() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join(".git")).unwrap();
    let det = detect_project(tmp.path());
    assert!(det.markers_first_is_git());
}

// --- .env filename detection ---------------------------------------------

#[test]
fn env_filename_variants() {
    assert!(is_env_filename(".env"));
    assert!(is_env_filename(".env.local"));
    assert!(is_env_filename(".env.production"));
    assert!(is_env_filename(".env.development"));
    assert!(is_env_filename(".env.test"));
    assert!(is_env_filename(".env.example"));
    assert!(is_env_filename(".env.sample"));
    assert!(is_env_filename(".env.staging"));
}

#[test]
fn env_filename_rejects_non_variants() {
    assert!(!is_env_filename("env"));
    assert!(!is_env_filename(".envrc"));
    assert!(!is_env_filename(".env2"));
    assert!(!is_env_filename(".env.foo.bar"));
    assert!(!is_env_filename(".env.Foo"));
    assert!(!is_env_filename("myenv"));
    // `<name>.env` dotfiles are recognized
    assert!(is_env_filename("db.env"));
    assert!(is_env_filename("local.env"));
}

#[test]
fn env_layer_extraction() {
    assert_eq!(env_layer(".env"), None);
    assert_eq!(env_layer(".env.local"), Some("local".into()));
    assert_eq!(env_layer(".env.production"), Some("production".into()));
}

// --- secret classification -------------------------------------------------

fn var(name: &str, value: &str) -> configctl_core::envfile::ParsedVariable {
    let p = parse_env(
        &format!("{name}={value}\n"),
        &configctl_core::envfile::ParseLimits::default(),
    );
    p.variables.into_iter().next().expect("one variable")
}

#[test]
fn password_name_classified_secret() {
    let v = var("DATABASE_PASSWORD", "x1y2z3w4q5r6s7t8u9");
    let res = classify_variable(&v, ".env", &EntropyScorer::default());
    assert!(res.is_secret_like());
    assert!(res
        .signals
        .iter()
        .any(|s| s.contains("DATABASE_PASSWORD") || s.contains("variable_name")));
}

#[test]
fn plain_config_name_classified_config() {
    let v = var("PORT", "3000");
    let res = classify_variable(&v, ".env", &EntropyScorer::default());
    assert!(!res.is_secret_like());
}

#[test]
fn openai_key_prefix_pattern_hits() {
    let v = var("OPENAI_API_KEY", "sk-test-CANARY1234567890");
    let res = classify_variable(&v, ".env", &EntropyScorer::default());
    assert!(res.is_secret_like());
    assert!(res
        .signals
        .iter()
        .any(|s| s.contains("token_pattern") || s.contains("variable_name")));
}

#[test]
fn empty_value_is_config() {
    let v = var("SOME_API_KEY", "");
    let res = classify_variable(&v, ".env", &EntropyScorer::default());
    assert_eq!(res.classification, Classification::Config);
}

#[test]
fn jwt_shape_detected() {
    let v = var("AUTH", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdef");
    let res = classify_variable(&v, ".env", &EntropyScorer::default());
    assert!(res.is_secret_like());
    assert!(res.signals.iter().any(|s| s.contains("jwt_like")));
}

#[test]
fn lexicon_is_extensible_table() {
    // The lexicon is a data table, not scattered if-statements: prove shape.
    assert!(NAME_LEXICON.iter().any(|e| e.needle == "API_KEY"));
    assert!(NAME_LEXICON.iter().all(|e| !e.needle.is_empty()));
}

// --- entropy scoring --------------------------------------------------------

#[test]
fn high_entropy_flagged_low_entropy_not() {
    let s = EntropyScorer::default();
    let high = "aB3$xZ9#kL2@pQ7!wJ4%";
    let low = "aaaaaa bbbbbb cccccc";
    assert!(s.score(high).0);
    assert!(!s.score(low).0);
}

#[test]
fn short_values_skip_entropy() {
    let s = EntropyScorer::default();
    assert!(!s.score("abc").0);
}

// --- config registry ---------------------------------------------------------

#[test]
fn config_registry_matches_known_files() {
    assert!(match_config_type("Cargo.toml"));
    assert!(match_config_type("package.json"));
    assert!(match_config_type("Dockerfile"));
    assert!(match_config_type("go.mod"));
    assert!(
        match_config_type("random.toml"),
        "generic .toml extension counts"
    );
    assert!(!match_config_type("random.txt"));
    assert!(!CONFIG_TYPES.is_empty());
}

// --- walker limits ----------------------------------------------------------

#[test]
fn walker_depth_limit_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    // Build a deep tree: 6 levels
    let mut p = tmp.path().to_path_buf();
    for i in 0..6 {
        p = p.join(format!("d{i}"));
        std::fs::create_dir_all(&p).unwrap();
    }
    std::fs::write(p.join("leaf.txt"), "x").unwrap();

    let limits = Limits {
        max_depth: 3,
        ..Limits::default()
    };
    let w = BoundedWalker::new(limits);
    let stats = w.walk(tmp.path(), &mut |_| true);
    assert!(matches!(
        stats.stop_reason,
        Some(configctl_discovery::walker::StopReason::DepthLimit)
    ));
}

#[test]
fn walker_file_count_limit_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    for i in 0..5 {
        std::fs::write(tmp.path().join(format!("f{i}")), "x").unwrap();
    }
    let limits = Limits {
        max_files_per_root: 3,
        ..Limits::default()
    };
    let w = BoundedWalker::new(limits);
    let stats = w.walk(tmp.path(), &mut |_| true);
    assert!(matches!(
        stats.stop_reason,
        Some(configctl_discovery::walker::StopReason::FileCountLimit)
    ));
}

#[test]
fn walker_symlinks_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let inside = tmp.path().join("inside.txt");
    std::fs::write(&inside, "x").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&inside, tmp.path().join("link.txt")).unwrap();
    }
    let w = BoundedWalker::new(Limits::default());
    let mut seen = Vec::new();
    w.walk(tmp.path(), &mut |v| {
        seen.push(v.path.clone());
        true
    });
    assert!(seen.contains(&inside));
    // v1.1: the symlink itself is yielded for mapping (kind symlink) but its
    // target is never followed — `inside.txt` appears exactly once.
    assert_eq!(seen.iter().filter(|p| *p == &inside).count(), 1);
}

#[test]
fn walker_symlink_dir_not_descended() {
    let tmp = tempfile::tempdir().unwrap();
    let realdir = tmp.path().join("realdir");
    std::fs::create_dir(&realdir).unwrap();
    std::fs::write(realdir.join("inner.txt"), "x").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&realdir, tmp.path().join("linkdir")).unwrap();
    }
    let w = BoundedWalker::new(Limits::default());
    let mut seen = Vec::new();
    w.walk(tmp.path(), &mut |v| {
        seen.push(v.path.clone());
        true
    });
    assert!(seen.iter().any(|p| *p == realdir.join("inner.txt")));
    // v1.1: the link itself is yielded for mapping, but nothing beneath it
    // may ever be traversed (the target is never followed).
    assert!(
        !seen
            .iter()
            .any(|p| p.starts_with(tmp.path().join("linkdir")) && *p != tmp.path().join("linkdir")),
        "symlinked directory must not be descended"
    );
}

#[test]
fn walker_exclusion_statistics() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join("node_modules")).unwrap();
    std::fs::write(tmp.path().join("node_modules/x.js"), "x").unwrap();
    std::fs::write(tmp.path().join("a.txt"), "x").unwrap();

    let limits = Limits::default();
    let rules = WalkRules {
        exclude_dirs: vec!["node_modules".into()],
    };
    let w = BoundedWalker::new(limits).with_rules(rules);
    let mut files = Vec::new();
    let stats = w.walk(tmp.path(), &mut |v| {
        files.push(v.path.clone());
        true
    });
    assert!(files.iter().any(|p| *p == tmp.path().join("a.txt")));
    assert!(!files
        .iter()
        .any(|p| p.starts_with(tmp.path().join("node_modules"))));
    assert!(stats.excluded > 0, "pruned directories must be counted");
}
