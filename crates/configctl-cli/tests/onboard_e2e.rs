//! `configctl onboard` end-to-end: writes a profile bundle and nothing else.

use configctl_cli::commands::onboard::run_onboard;
use configctl_core::command::FakeCommandRunner;
use std::path::Path;

fn world(tmp: &Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let home = tmp.join("home");
    let project = tmp.join("project");
    let out = tmp.join("bundle");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        home.join(".bashrc"),
        "export EDITOR=nano\nexport GITHUB_TOKEN=ghp_zzzzzzzzzzzz\n",
    )
    .unwrap();
    std::fs::write(home.join(".profile"), "export EDITOR=vim\n").unwrap();
    std::fs::write(project.join(".env"), "PORT=8080\n").unwrap();
    (home, project, out)
}

#[test]
fn onboard_writes_only_the_profile_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, project, out) = world(tmp.path());
    let bashrc_before = std::fs::read_to_string(home.join(".bashrc")).unwrap();
    let runner = FakeCommandRunner::new();

    let res = run_onboard(
        &[project.to_string_lossy().into_owned()],
        &[],
        Some(out.to_str().unwrap()),
        Some(&home),
        false,
        &runner,
    );
    assert!(res.error.is_none(), "{:?}", res.error);
    assert_eq!(res.exit_code, 0);
    assert!(res.text.contains("Step 1/4"));
    assert!(res.text.contains("Step 4/4"));
    assert!(res.text.contains("Nothing has been changed yet"));
    assert!(res.data["changed"] == false);

    // The bundle exists and is a loadable profile directory.
    assert!(out.join("profile.toml").is_file());
    assert!(configctl_core::profile_load::load_profile_dir(&out).is_ok());

    // Nothing else on the machine was touched.
    assert_eq!(
        std::fs::read_to_string(home.join(".bashrc")).unwrap(),
        bashrc_before
    );
    assert!(!home.join(".config/configctl/env.sh").exists());
    assert!(!home
        .join(".config/environment.d/90-configctl.conf")
        .exists());

    // The secret-shaped value never appears in the report.
    assert!(!res.text.contains("ghp_zzzzzzzzzzzz"));
    assert!(!res.data.to_string().contains("ghp_zzzzzzzzzzzz"));
}

#[test]
fn onboard_refuses_to_overwrite_an_existing_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, project, out) = world(tmp.path());
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("keep.txt"), "mine\n").unwrap();
    let runner = FakeCommandRunner::new();
    let roots = [project.to_string_lossy().into_owned()];

    let refused = run_onboard(
        &roots,
        &[],
        Some(out.to_str().unwrap()),
        Some(&home),
        false,
        &runner,
    );
    assert_eq!(refused.exit_code, 5);
    assert!(refused.error.is_some());
    assert_eq!(
        std::fs::read_to_string(out.join("keep.txt")).unwrap(),
        "mine\n"
    );

    // --force proceeds and the pre-existing file is left alone.
    let forced = run_onboard(
        &roots,
        &[],
        Some(out.to_str().unwrap()),
        Some(&home),
        true,
        &runner,
    );
    assert!(forced.error.is_none(), "{:?}", forced.error);
    assert_eq!(
        std::fs::read_to_string(out.join("keep.txt")).unwrap(),
        "mine\n"
    );
    assert!(out.join("profile.toml").is_file());
}
