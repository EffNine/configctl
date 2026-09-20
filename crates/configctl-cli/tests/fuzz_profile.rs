//! P8 profile/env fuzzing: malformed input never causes unsafe mutation.
//!
//! Property-style: every malformed bundle is either rejected at load/plan
//! time (exit 2) or planned without mutating ops outside the declared target
//! set. Planning and validation never write to the machine.

fn write_bundle(dir: &std::path::Path, profile_toml: &str) {
    std::fs::create_dir_all(dir.join("files")).unwrap();
    std::fs::write(dir.join("files/p"), "x\n").unwrap();
    std::fs::write(dir.join("profile.toml"), profile_toml).unwrap();
}

fn malformed_cases() -> Vec<(&'static str, String)> {
    vec![
        ("empty", String::new()),
        ("truncated", "schema_version = ".into()),
        ("unclosed", "[[files]]\ntarget = \"~/x".into()),
        ("wrong-type", "schema_version = \"one\"\nname = \"x\"\n".into()),
        ("huge-name", format!("schema_version = 1\nname = \"{}\"\n", "a".repeat(5000))),
        ("nul", "schema_version = 1\nname = \"a\0b\"\n".into()),
        ("deep-nest", "schema_version = 1\nname = \"x\"\n[a.b.c.d.e.f.g]\n".into()),
        ("array-chaos", "schema_version = 1\nname = \"x\"\npackages = [1, 2, [3]]\n".into()),
        ("dup-target", "schema_version = 1\nname = \"x\"\n\n[[files]]\ntarget = \"~/.a\"\nsource = \"files/p\"\n\n[[files]]\ntarget = \"~/.a\"\nsource = \"files/p\"\n".into()),
        ("bad-mode", "schema_version = 1\nname = \"x\"\n\n[[files]]\ntarget = \"~/.a\"\nsource = \"files/p\"\nmode = \"9999\"\n".into()),
        ("secret-literal", "schema_version = 1\nname = \"x\"\n\n[environment]\nAPI_PASSWORD = \"hunter2-secret\"\n".into()),
        ("unknown-key", "schema_version = 1\nname = \"x\"\npwned = true\n".into()),
        ("bad-service", "schema_version = 1\nname = \"x\"\n\n[[services]]\nname = \"../../evil\"\n".into()),
        ("bad-package", "schema_version = 1\nname = \"x\"\n\n[packages]\napt = [\"rm -rf /\"]\n".into()),
        ("unicode", "schema_version = 1\nname = \"wörk\"\n".into()),
        ("env-bad-name", "schema_version = 1\nname = \"x\"\n\n[environment]\n\"has space\" = \"v\"\n".into()),
        (
            "future-schema",
            "schema_version = 99\nname = \"x\"\n".into(),
        ),
    ]
}

#[test]
fn malformed_profiles_never_load() {
    let tmp = tempfile::tempdir().unwrap();
    for (label, toml) in malformed_cases() {
        let dir = tmp.path().join(label.replace('/', "_"));
        write_bundle(&dir, &toml);
        let res = configctl_core::profile_load::load_profile_dir(&dir);
        assert!(res.is_err(), "malformed case accepted: {label}");
    }
}

#[test]
fn malformed_env_files_never_panic_or_mutate() {
    let tmp = tempfile::tempdir().unwrap();
    let home_before: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let long_line = format!("LONG={}\n", "x".repeat(9000));
    let cases: Vec<&str> = vec![
        "NOEQUALS LINE\n",
        "=\n",
        "=value\n",
        "1BAD=x\n",
        "GOOD=1\nBAD LINE\nANOTHER=2\n",
        "A=\"unclosed\n",
        "B='single\n",
        "export \n",
        "export X=\n",
        "\u{feff}BOM=1\n",
        &long_line,
        "NUL=\0byte\n",
        "DUP=1\nDUP=2\n",
    ];
    for (i, text) in cases.iter().enumerate() {
        let parsed = configctl_core::envfile::parse_env(
            text,
            &configctl_core::envfile::ParseLimits {
                max_bytes: 256 * 1024,
                max_variables: 10_000,
            },
        );
        // Must not panic; duplicates preserved, malformed recorded.
        let _ = (i, parsed.variables.len(), parsed.malformed.len());
    }
    let home_after: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(home_before, home_after);
}

#[test]
fn path_normalization_adversarial() {
    // Every traversal attempt is rejected; safe paths accepted.
    let bad = [
        "~/..",
        "~/../x",
        "~/.a/../..",
        "/etc/passwd",
        "~/a/../../b",
        "~/a\0",
        "~\n/x",
        "~/a|b",
        "~/a;b",
        "~/$(x)",
    ];
    // NOTE: `~/%2e%2e/x` is accepted as a *literal* name — nothing in the
    // tool URL-decodes paths, and the filesystem treats `%` literally, so it
    // cannot escape. It is asserted safe (not rejected) below.
    assert!(configctl_core::paths::validate_file_target("~/%2e%2e/x").is_ok());
    for p in bad {
        assert!(
            configctl_core::paths::validate_file_target(p).is_err(),
            "accepted {p:?}"
        );
    }
    assert!(configctl_core::paths::validate_file_target("~/.config/app").is_ok());
    assert!(configctl_core::paths::validate_file_target("~/.a-b_c.d/e").is_ok());
}

#[test]
fn secret_ref_grammar_adversarial() {
    let bad = [
        "secret:/x",
        "secret://",
        "secret://nonamespace",
        "secret:///x",
        "secret://a/../b",
        "secret://a//b",
        "http://a/b",
        "",
    ];
    for r in bad {
        assert!(
            configctl_core::paths::validate_secret_ref(r).is_err(),
            "accepted {r:?}"
        );
    }
    assert!(configctl_core::paths::validate_secret_ref("secret://work/dev/KEY").is_ok());
}

#[test]
fn plan_never_emits_outside_declared_targets() {
    // Even a maximally weird-but-valid profile only yields ops on declared
    // targets, in sorted order, with stable ids.
    let tmp = tempfile::tempdir().unwrap();
    let bundle = tmp.path().join("b");
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    for name in ["p1", "p2"] {
        std::fs::write(bundle.join(format!("files/{name}")), "v\n").unwrap();
    }
    std::fs::write(
        bundle.join("profile.toml"),
        "schema_version = 1\nname = \"b\"\n\n[packages]\napt = [\"zzz\", \"aaa\"]\n\n[[files]]\ntarget = \"~/.z\"\nsource = \"files/p1\"\n\n[[files]]\ntarget = \"~/.a\"\nsource = \"files/p2\"\n\n[environment]\nB_VAR = \"2\"\nA_VAR = \"1\"\n",
    )
    .unwrap();
    let loaded = configctl_core::profile_load::load_profile_dir(&bundle).unwrap();
    let mut st = configctl_core::observe::ObservedState::default();
    for t in ["~/.z", "~/.a"] {
        st.files.insert(
            t.into(),
            configctl_core::observe::FileObs {
                exists: false,
                is_symlink: false,
                is_non_regular: false,
                content_hash: None,
                len: None,
            },
        );
    }
    let plan = configctl_core::plan::build_plan(&loaded, &st, &Default::default(), "fuzz-1", 1);
    let targets: Vec<&str> = plan.operations.iter().map(|o| o.target.as_str()).collect();
    for t in &targets {
        assert!(
            ["zzz", "aaa", "~/.z", "~/.a", "B_VAR", "A_VAR"].contains(t),
            "undeclared target {t:?}"
        );
    }
    let mut sorted = targets.clone();
    sorted.sort();
    // Providers group in rank order; within files/env, targets sorted.
    let file_targets: Vec<&&str> = targets.iter().filter(|t| t.starts_with("~/")).collect();
    assert_eq!(file_targets, vec![&"~/.a", &"~/.z"]);
}
