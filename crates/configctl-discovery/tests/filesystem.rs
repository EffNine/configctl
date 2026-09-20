//! P4 tests: dotfiles, project roles, symlinks, mounts, completeness.

use configctl_core::command::FakeCommandRunner;
use configctl_core::governor::GovernorBudgets;
use configctl_discovery::filesystem::{ProjectFileRole, categorize_dotfile, classify_project_file};
use configctl_discovery::mounts::{MountDecision, MountRecord, collect, decide};
use configctl_discovery::scanner::{ScanOptions, Scanner};
use std::path::Path;

fn scan_fixture(root: &Path) -> configctl_discovery::scanner::ScanResult {
    let runner = FakeCommandRunner::new();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![root.to_path_buf()],
        limits: Default::default(),
        governor: Default::default(),
    };
    scanner.scan(&opts, &runner)
}

#[test]
fn dotfiles_discovered_broadly_with_categories() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(".bashrc"), "x\n").unwrap();
    std::fs::write(tmp.path().join(".zshrc"), "x\n").unwrap();
    std::fs::create_dir_all(tmp.path().join(".config/nvim")).unwrap();
    std::fs::write(tmp.path().join(".config/nvim/init.lua"), "x\n").unwrap();
    std::fs::write(tmp.path().join(".mystery-tool-rc"), "x\n").unwrap();

    let result = scan_fixture(tmp.path());
    // Dotfiles by filename: .bashrc, .zshrc, .mystery-tool-rc
    // (.config is a dot-dir; init.lua inside it is not itself a dotfile).
    assert!(result.filesystem.dotfiles_found >= 3, "{:?}", result.filesystem.dotfiles_found);
    let cats: Vec<&str> = result.dotfiles.iter().map(|d| d.category.as_str()).collect();
    assert!(cats.contains(&"shell"));
    // Unknown dotfiles are still mapped, never dropped.
    let mystery = result.dotfiles.iter().find(|d| d.name == ".mystery-tool-rc").expect("mapped");
    assert_eq!(mystery.category, "unknown");
    assert!(!mystery.reason.is_empty());
    assert_eq!(categorize_dotfile(".bashrc"), "shell");
    assert_eq!(categorize_dotfile(".gitconfig"), "vcs");
    assert_eq!(categorize_dotfile(".whatever"), "unknown");
}

#[test]
fn project_content_roles_distinguish_source_from_generated() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::create_dir_all(proj.join("out")).unwrap();
    std::fs::create_dir_all(proj.join("docs")).unwrap();
    std::fs::write(proj.join("Cargo.toml"), "[package]\n").unwrap();
    std::fs::write(proj.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(proj.join("out/bundle.js"), "x\n").unwrap();
    std::fs::write(proj.join("docs/guide.md"), "x\n").unwrap();

    let result = scan_fixture(tmp.path());
    assert_eq!(result.projects.len(), 1);
    let content = result
        .project_contents
        .iter()
        .find(|c| c.project == "proj")
        .expect("content summary");
    let roles = &content.roles;
    assert_eq!(roles.get("source"), Some(&1));
    assert_eq!(roles.get("manifest"), Some(&1));
    assert_eq!(roles.get("generated"), Some(&1));
    assert_eq!(roles.get("documentation"), Some(&1));

    // Pure unit checks for the role classifier.
    let (role, _) = classify_project_file(Path::new("/p/src/main.rs"), false, 10);
    assert_eq!(role, ProjectFileRole::Source);
    let (role, _) = classify_project_file(Path::new("/p/target/debug/app"), false, 10);
    assert_eq!(role, ProjectFileRole::Generated);
    let (role, _) = classify_project_file(Path::new("/p/Cargo.lock"), false, 10);
    assert_eq!(role, ProjectFileRole::Lockfile);
}

#[test]
fn weak_markers_do_not_declare_projects() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(".nvmrc"), "20\n").unwrap();
    std::fs::write(tmp.path().join(".editorconfig"), "root = true\n").unwrap();
    let result = scan_fixture(tmp.path());
    assert!(result.projects.is_empty(), "config-only dir is not a project");
    // …but the files are still mapped as dotfiles.
    assert!(result.filesystem.dotfiles_found >= 2);
}

#[test]
fn symlinks_mapped_with_targets_in_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real.txt");
    std::fs::write(&real, "data\n").unwrap();
    std::os::unix::fs::symlink(&real, tmp.path().join("link.txt")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("cycle-b"), tmp.path().join("cycle-a")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("cycle-a"), tmp.path().join("cycle-b")).unwrap();

    let result = scan_fixture(tmp.path());
    assert!(result.filesystem.counters.symlinks >= 3);
    let link = result
        .filesystem
        .symlinks
        .iter()
        .find(|s| s.path.ends_with("link.txt"))
        .expect("link mapped");
    assert!(link.target_exists);
    assert!(link.target.ends_with("real.txt"));
    // Cycle recorded with explicit flag.
    assert!(
        result.filesystem.symlinks.iter().any(|s| s.cycle == Some(true)),
        "cycle must be flagged"
    );
    assert!(result.statistics.symlinks_found >= 3);
}

#[test]
fn mount_table_recorded_and_policy_explicit() {
    let result = scan_fixture(std::env::temp_dir().as_path());
    assert!(!result.mounts.is_empty(), "mounts must be discovered");
    assert!(result.mounts.iter().any(|m| m.mountpoint == "/"));
    let nfs = MountRecord {
        mountpoint: "/mnt/nfs".into(),
        fstype: "nfs".into(),
        device: "srv:/x".into(),
        options: vec![],
        remote: true,
        pseudo: false,
    };
    assert_eq!(decide(&nfs, false, false), MountDecision::RecordOnly);
    let ext4 = MountRecord {
        mountpoint: "/home".into(),
        fstype: "ext4".into(),
        device: "/dev/sda1".into(),
        options: vec![],
        remote: false,
        pseudo: false,
    };
    assert_eq!(decide(&ext4, false, false), MountDecision::Scan);
    let _ = collect;
}

#[test]
fn budget_exhaustion_reports_partial_completeness() {
    let tmp = tempfile::tempdir().unwrap();
    for i in 0..20 {
        std::fs::write(tmp.path().join(format!("f{i}.txt")), b"x").unwrap();
    }
    let runner = FakeCommandRunner::new();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![tmp.path().to_path_buf()],
        limits: Default::default(),
        governor: GovernorBudgets { max_file_count: 5, ..GovernorBudgets::default() },
    };
    let result = scanner.scan(&opts, &runner);
    assert_eq!(
        result.completeness.status,
        Some(configctl_core::inventory::ScanStatus::Partial)
    );
    assert!(result.completeness.skipped >= 1);
    assert!(result.completeness.reasons.contains_key("budget_exhausted"));
    assert!(result.completeness.completeness_pct() < 100.0);
}
