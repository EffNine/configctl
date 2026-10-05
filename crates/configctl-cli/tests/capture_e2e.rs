//! P2 capture integration + security tests (disposable fixtures only).
//!
//! Fixture:
//!
//! ```text
//! fixture/
//! ├── project-a/ (.git, .env with canary, .env.example, Cargo.toml)
//! ├── project-b/ (.env.production with canary, package.json, src/)
//! └── home/ (.gitconfig, .editorconfig, symlink, oversized, secret-bearing)
//! ```

use configctl_cli::commands::capture;
use configctl_core::capture as core_capture;
use configctl_core::command::FakeCommandRunner;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const CANARY_A: &str = "super-secret-test-value-aaa111";
const CANARY_B: &str = "another-secret-value-bbb222";
const CANARY_C: &str = "sk-live-canary-ccc333999";

fn build_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    // project-a
    let pa = root.join("project-a");
    std::fs::create_dir_all(pa.join(".git")).unwrap();
    std::fs::write(
        pa.join(".env"),
        format!("OPENAI_API_KEY={CANARY_A}\nDATABASE_PASSWORD={CANARY_B}\nPORT=3000\n"),
    )
    .unwrap();
    std::fs::write(
        pa.join(".env.example"),
        "OPENAI_API_KEY=\nDATABASE_PASSWORD=\nPORT=\n",
    )
    .unwrap();
    std::fs::write(pa.join("Cargo.toml"), "[package]\nname=\"a\"\n").unwrap();
    // Malformed line (must not crash capture).
    std::fs::write(
        pa.join(".env.local"),
        "GOOD=1\nTHIS LINE HAS NO EQUALS\nPORT=4000\n",
    )
    .unwrap();
    // project-b
    let pb = root.join("project-b");
    std::fs::create_dir_all(pb.join("src")).unwrap();
    std::fs::write(
        pb.join(".env.production"),
        format!("PROD_TOKEN={CANARY_C}\nDEBUG=false\n"),
    )
    .unwrap();
    std::fs::write(pb.join("package.json"), "{\"name\":\"b\"}\n").unwrap();
    // home
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(
        home.join(".gitconfig"),
        "[user]\n\tname = Test\n\temail = test@example.com\n",
    )
    .unwrap();
    std::fs::write(home.join(".editorconfig"), "root = true\n").unwrap();
    // symlink in home (must be rejected, never followed).
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(home.join(".gitconfig"), home.join(".tool-versions")).unwrap();
    }
    // oversized file (must be excluded, never copied).
    std::fs::write(home.join(".nvmrc"), vec![b'x'; 300 * 1024]).unwrap();
    // secret-bearing file (must be excluded, never copied).
    std::fs::write(
        home.join(".python-version"),
        "password = hunter2-secret-value\n",
    )
    .unwrap();
    (tmp, root, pa, home)
}

fn snapshot(root: &Path) -> BTreeMap<String, (u64, u64)> {
    let mut map = BTreeMap::new();
    let walker =
        configctl_discovery::walker::BoundedWalker::new(configctl_core::limits::Limits::default());
    walker.walk(root, &mut |v| {
        let key = v.path.to_string_lossy().into_owned();
        let size = std::fs::metadata(&v.path).map(|m| m.len()).unwrap_or(0);
        let mtime = std::fs::metadata(&v.path)
            .and_then(|m| m.modified())
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        map.insert(key, (size, mtime));
        true
    });
    map
}

fn bundle_contains(bundle: &Path, needle: &str) -> bool {
    let mut found = false;
    let mut stack = vec![bundle.to_path_buf()];
    while let Some(p) = stack.pop() {
        let entries = match std::fs::read_dir(&p) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.filter_map(|c| c.ok()) {
            let path = e.path();
            if let Ok(m) = std::fs::symlink_metadata(&path) {
                if m.file_type().is_dir() {
                    stack.push(path);
                } else if m.file_type().is_file() {
                    if let Ok(bytes) = std::fs::read(&path) {
                        if bytes.len() < 4 * 1024 * 1024
                            && String::from_utf8_lossy(&bytes).contains(needle)
                        {
                            found = true;
                        }
                    }
                }
            }
        }
    }
    found
}

fn core_capture_to(
    fixture_root: &Path,
    home: &Path,
    out: &Path,
    runner: &FakeCommandRunner,
) -> core_capture::CaptureResult {
    // Scan the fixture with the P1 scanner (same runner).
    let mut scanner = configctl_discovery::scanner::Scanner::new();
    let opts = configctl_discovery::scanner::ScanOptions {
        roots: vec![fixture_root.to_path_buf()],
        limits: Default::default(),
        governor: Default::default(),
    };
    let scan = scanner.scan(&opts, runner);
    let view = {
        use core_capture::scan_view as stub;
        stub::ScanView {
            projects: scan
                .projects
                .iter()
                .map(|p| stub::ProjectView {
                    path: p.path.clone(),
                    name: p.name.clone(),
                    vcs: p.vcs.clone(),
                    hints: p.hints.clone(),
                })
                .collect(),
            env_files: scan
                .env_files
                .iter()
                .map(|e| stub::EnvFileView {
                    path: e.path.clone(),
                    project: e.project.clone(),
                    variable_names: e.variable_names.clone(),
                    classifications: e
                        .classifications
                        .iter()
                        .map(|c| stub::VarClass {
                            name: c.name.clone(),
                            classification: c.classification.clone(),
                        })
                        .collect(),
                })
                .collect(),
            config_files: scan
                .config_files
                .iter()
                .map(|c| stub::ConfigFileView {
                    path: c.path.clone(),
                    name: c.name.clone(),
                    project: c.project.clone(),
                })
                .collect(),
            distro: scan.system.distro.clone(),
            excluded_paths: scan.statistics.excluded_paths,
            warnings: scan.warnings.clone(),
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
        }
    };
    let values = scanner.registry().snapshot_values();
    let cap_opts = core_capture::CaptureOptions {
        profile_name: "fixture".into(),
        description: Some("fixture capture".into()),
        scan_roots: vec![fixture_root.to_path_buf()],
        home: Some(home.to_path_buf()),
        limits: Default::default(),
    };
    let result = core_capture::run_capture(&cap_opts, &view, runner, &values).expect("capture");
    core_capture::write_bundle(&result, out, false).expect("write bundle");
    result
}

#[test]
fn capture_produces_expected_bundle() {
    let (_tmp, root, _pa, home) = build_fixture();
    let out = root.join("out-profile");
    let runner = FakeCommandRunner::new();
    let result = core_capture_to(&root, &home, &out, &runner);

    assert!(out.join("profile.toml").exists(), "profile.toml exists");
    assert!(
        out.join("secrets.manifest.toml").exists(),
        "secrets.manifest.toml exists"
    );
    // Env schemas for both projects.
    assert!(
        out.join("env/project-a.toml").exists(),
        "env/project-a.toml exists"
    );
    assert!(
        out.join("env/project-b.toml").exists(),
        "env/project-b.toml exists"
    );
    // Home payloads: safe files copied; symlink/oversize/secret excluded.
    assert!(
        out.join("files/home/gitconfig").exists(),
        "gitconfig payload exists"
    );
    assert!(
        out.join("files/home/editorconfig").exists(),
        "editorconfig payload exists"
    );
    assert!(
        !out.join("files/home/tool-versions").exists(),
        "symlink never copied"
    );
    assert!(
        !out.join("files/home/nvmrc").exists(),
        "oversized never copied"
    );
    assert!(
        !out.join("files/home/python-version").exists(),
        "secret-bearing never copied"
    );
    // Summary counts.
    assert_eq!(result.summary.projects, 2);
    assert!(result.summary.env_schemas >= 2);
    assert!(result.summary.secrets >= 2);
}

#[test]
fn capture_never_modifies_sources() {
    let (_tmp, root, _pa, home) = build_fixture();
    let before = snapshot(&root);
    let out = root.join("out2");
    let runner = FakeCommandRunner::new();
    let _ = core_capture_to(&root, &home, &out, &runner);
    // Remove the output dir from the comparison (it is the only allowed write).
    let after_full = snapshot(&root);
    let after: BTreeMap<_, _> = after_full
        .into_iter()
        .filter(|(k, _)| !k.starts_with(&out.to_string_lossy().into_owned()))
        .collect();
    let before_filtered: BTreeMap<_, _> = before
        .into_iter()
        .filter(|(k, _)| !k.starts_with(&out.to_string_lossy().into_owned()))
        .collect();
    assert_eq!(before_filtered, after, "sources must be unmodified");
}

#[test]
fn no_secret_value_anywhere_in_bundle() {
    let (_tmp, root, _pa, home) = build_fixture();
    let out = root.join("out3");
    let runner = FakeCommandRunner::new();
    let _ = core_capture_to(&root, &home, &out, &runner);
    for canary in [CANARY_A, CANARY_B, CANARY_C, "hunter2-secret-value"] {
        assert!(!bundle_contains(&out, canary), "canary leaked: {canary}");
    }
    // Also check individual artifact classes explicitly.
    let profile = std::fs::read_to_string(out.join("profile.toml")).unwrap();
    let manifest = std::fs::read_to_string(out.join("secrets.manifest.toml")).unwrap();
    for canary in [CANARY_A, CANARY_B, CANARY_C] {
        assert!(!profile.contains(canary), "secret in profile");
        assert!(!manifest.contains(canary), "secret in manifest");
    }
    for entry in walk_files(&out.join("env")) {
        let text = std::fs::read_to_string(&entry).unwrap();
        for canary in [CANARY_A, CANARY_B, CANARY_C] {
            assert!(!text.contains(canary), "secret in env schema");
        }
    }
    for entry in walk_files(&out.join("files")) {
        let bytes = std::fs::read(&entry).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        for canary in [CANARY_A, CANARY_B, CANARY_C] {
            assert!(!text.contains(canary), "secret in file payload");
        }
    }
}

fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let entries = match std::fs::read_dir(&p) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.filter_map(|c| c.ok()) {
            let path = e.path();
            if let Ok(m) = std::fs::symlink_metadata(&path) {
                if m.file_type().is_dir() {
                    stack.push(path);
                } else if m.file_type().is_file() {
                    out.push(path);
                }
            }
        }
    }
    out.sort();
    out
}

#[test]
fn capture_output_redacted_in_all_sinks() {
    let (_tmp, root, _pa, _home) = build_fixture();
    let runner = FakeCommandRunner::new();
    let out_dir = root.join("out-json");
    let cap = capture::run_capture(
        Some("fixture"),
        &[root.to_string_lossy().into_owned()],
        &[],
        Some(&out_dir.to_string_lossy()),
        false,
        None,
        false,
        None,
        &runner,
    );
    assert!(cap.error_envelope.is_none());
    let res = cap.result.as_ref().unwrap();
    // JSON envelope redacted.
    let env = configctl_cli::render::Envelope::capture_ok(res, &cap.written, &cap.out_dir, false);
    let json = cap.registry.redact(&env.to_json());
    for canary in [CANARY_A, CANARY_B, CANARY_C] {
        assert!(!json.contains(canary), "canary in JSON");
    }
    let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    // Human rendering redacted.
    let human = capture::render_human(&cap, true);
    let human = cap.registry.redact(&human);
    for canary in [CANARY_A, CANARY_B, CANARY_C] {
        assert!(!human.contains(canary), "canary in human output");
    }
}

#[test]
fn dry_run_writes_nothing() {
    let (_tmp, root, _pa, _home) = build_fixture();
    let runner = FakeCommandRunner::new();
    let out_dir = root.join("out-dry");
    let cap = capture::run_capture(
        Some("fixture"),
        &[root.to_string_lossy().into_owned()],
        &[],
        Some(&out_dir.to_string_lossy()),
        false,
        None,
        true,
        None,
        &runner,
    );
    assert!(cap.error_envelope.is_none());
    assert!(cap.dry_run);
    assert!(!out_dir.exists(), "dry-run must not create the output dir");
    assert!(!cap.written.is_empty(), "dry-run still previews writes");
}

#[test]
fn round_trip_capture_serialize_deserialize_validate() {
    let (_tmp, root, _pa, home) = build_fixture();
    let out = root.join("out-rt");
    let runner = FakeCommandRunner::new();
    let result = core_capture_to(&root, &home, &out, &runner);
    // profile.toml round-trip.
    let text = std::fs::read_to_string(out.join("profile.toml")).unwrap();
    let p = configctl_core::profile::Profile::from_toml(&text).unwrap();
    assert!(p.validate().is_empty());
    assert_eq!(p, {
        let mut c = result.profile.clone();
        c.canonicalize();
        c
    });
    // env schemas round-trip.
    for entry in walk_files(&out.join("env")) {
        let text = std::fs::read_to_string(&entry).unwrap();
        let s = configctl_core::profile::EnvSchema::from_toml(&text).unwrap();
        assert!(s.validate().is_empty());
    }
    // manifest round-trip.
    let text = std::fs::read_to_string(out.join("secrets.manifest.toml")).unwrap();
    let m = configctl_core::profile::SecretManifest::from_toml(&text).unwrap();
    assert!(m.validate().is_empty());
}

#[test]
fn deterministic_output_ordering() {
    let (_tmp, root, _pa, home) = build_fixture();
    let runner = FakeCommandRunner::new();
    let r1 = core_capture_to(&root, &home, &root.join("o1"), &runner);
    let runner2 = FakeCommandRunner::new();
    let r2 = core_capture_to(&root, &home, &root.join("o2"), &runner2);
    let t1 = std::fs::read_to_string(root.join("o1/profile.toml")).unwrap();
    let t2 = std::fs::read_to_string(root.join("o2/profile.toml")).unwrap();
    // Strip the informational timestamp before comparing.
    let strip = |t: &str| {
        t.lines()
            .filter(|l| !l.trim_start().starts_with("captured_at"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(strip(&t1), strip(&t2));
    let _ = (r1, r2);
}

#[test]
fn malformed_env_handled_safely() {
    // The fixture already contains `.env.local` with a malformed line; the
    // fact that capture succeeded (asserted in other tests) proves safe
    // handling. Here we assert the malformed file was still discovered and
    // did not poison the schema.
    let (_tmp, root, _pa, home) = build_fixture();
    let out = root.join("out-mal");
    let runner = FakeCommandRunner::new();
    let _result = core_capture_to(&root, &home, &out, &runner);
    let schema_path = out.join("env/project-a.toml");
    assert!(schema_path.exists());
    let text = std::fs::read_to_string(&schema_path).unwrap();
    assert!(text.contains("GOOD"));
}

// --- F1 (v1.3.1): secret-bearing home payloads are excluded, never copied ---

/// Scoped `HOME` override for the CLI capture path (which reads the process
/// `HOME`). Serialized so env mutations never race within this binary.
struct HomeGuard {
    _g: std::sync::MutexGuard<'static, ()>,
    prev: Option<std::ffi::OsString>,
}

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl HomeGuard {
    fn set(home: &Path) -> Self {
        let g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", home);
        Self { _g: g, prev }
    }
}

impl Drop for HomeGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(p) => std::env::set_var("HOME", p),
            None => std::env::remove_var("HOME"),
        }
    }
}

#[test]
fn secret_bearing_dotfile_excluded_from_dry_run_and_bundle() {
    // F1 reproduction (field validation): a home dotfile whose *content*
    // contains a registered secret value must be excluded before anything is
    // written. Dry-run must not list it as "would write"; the real capture
    // must succeed (not abort mid-write) with a clean bundle.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let canary = "sk-live-canary-bashrc-9f3a2b7c";
    std::fs::write(
        home.join(".bashrc"),
        format!("export GITHUB_TOKEN={canary}\nexport EDITOR=vim\n"),
    )
    .unwrap();
    std::fs::write(home.join(".gitconfig"), "[user]\n\tname = Test\n").unwrap();
    // A project .env registers the same value in the scanner's registry.
    let proj = root.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join(".env"), format!("GITHUB_TOKEN={canary}\n")).unwrap();

    let runner = FakeCommandRunner::new();
    let _home_guard = HomeGuard::set(&home);

    // Dry run: the file is excluded, never previewed as a write.
    let out_dry = root.join("out-dry");
    let dry = capture::run_capture(
        Some("fixture"),
        &[root.to_string_lossy().into_owned()],
        &[],
        Some(&out_dry.to_string_lossy()),
        false,
        None,
        true,
        None,
        &runner,
    );
    assert!(dry.error_envelope.is_none());
    assert!(
        !dry.written.iter().any(|w| w.contains("bashrc")),
        "dry-run listed a secret-bearing file as a write: {:?}",
        dry.written
    );
    assert!(!out_dry.exists(), "dry-run must not create the output dir");
    let dry_res = dry.result.as_ref().unwrap();
    assert!(dry_res
        .summary
        .excluded
        .iter()
        .any(|e| e.contains(".bashrc") && e.contains("secret value")));

    // Real capture: succeeds with the file excluded; bundle carries no canary.
    let out = root.join("out");
    let cap = capture::run_capture(
        Some("fixture"),
        &[root.to_string_lossy().into_owned()],
        &[],
        Some(&out.to_string_lossy()),
        false,
        None,
        false,
        None,
        &runner,
    );
    assert!(
        cap.error_envelope.is_none(),
        "capture must succeed with the file excluded: {:?}",
        cap.error_envelope
    );
    assert!(!out.join("files/home/bashrc").exists());
    assert!(out.join("files/home/gitconfig").exists());
    assert!(
        !bundle_contains(&out, canary),
        "canary leaked into the bundle"
    );
}
