//! v1.2 E5 move-mode assessment + patch rendering (core, read-only + pure).

use configctl_core::envmap;
use configctl_core::envmove::{assess_move, build_patch, MoveError, MAX_RC_BYTES};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SECRET_VALUE: &str = "ghp_zzzzzzzzzzzzzzzzzzzz";

fn entries(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// A temp home whose canonical file already matches `entries` (post-apply
/// state), plus the given rc files.
fn home_with(entries: &[(String, String)], rcs: &[(&str, &str)]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let canonical = envmap::canonical_env_file(entries);
    let dir = home.join(".config/configctl");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("env.sh"), canonical.as_bytes()).unwrap();
    for (rel, body) in rcs {
        std::fs::write(home.join(rel), body.as_bytes()).unwrap();
    }
    tmp
}

fn block() -> String {
    envmap::include_block()
}

#[test]
fn managed_match_with_include_block_is_eligible() {
    let es = entries(&[("EDITOR", "vim")]);
    let body = format!("export EDITOR=vim\n{}", block());
    let tmp = home_with(&es, &[(".bashrc", &body)]);
    let a = assess_move(tmp.path(), &es).expect("assess");
    assert_eq!(a.eligible.len(), 1);
    let e = &a.eligible[0];
    assert_eq!(
        (e.file.as_str(), e.line, e.name.as_str()),
        ("~/.bashrc", 1, "EDITOR")
    );
    assert_eq!(e.original, "export EDITOR=vim");
    assert!(a
        .files
        .iter()
        .any(|f| f.file == "~/.bashrc" && f.refused.is_none()));
}

#[test]
fn eligibility_matrix_reports_explicit_reasons() {
    let es = entries(&[("EDITOR", "vim")]);
    let body = format!(
        "export EDITOR=vim\nexport EDITOR=nano\nexport LANG=en_US.UTF-8\n\
         PATH=/usr/bin\nHOST_ALIAS=$(hostname)\n\
         export GITHUB_TOKEN={SECRET_VALUE}\nsource ~/.extra\n{}",
        block()
    );
    let tmp = home_with(&es, &[(".bashrc", &body)]);
    let a = assess_move(tmp.path(), &es).expect("assess");

    // Exactly one eligible line (the matching EDITOR).
    assert_eq!(a.eligible.len(), 1);
    assert_eq!(a.eligible[0].line, 1);

    let reason = |line: usize| {
        a.ineligible
            .iter()
            .find(|i| i.line == line)
            .unwrap_or_else(|| panic!("no ineligible entry for line {line}"))
            .reason
            .clone()
    };
    assert!(
        reason(2).contains("differs from the managed value"),
        "{:?}",
        reason(2)
    );
    assert!(reason(3).contains("not in the profile"), "{:?}", reason(3));
    assert!(reason(4).contains("never moved"), "{:?}", reason(4)); // PATH special
    assert!(reason(5).contains("left alone"), "{:?}", reason(5)); // manual
    assert!(reason(6).contains("secret"), "{:?}", reason(6)); // secret
    assert!(reason(7).contains("not a setting"), "{:?}", reason(7)); // structure

    // The secret value appears nowhere in the assessment or the patch.
    let patch = build_patch(&a, 1_700_000_000);
    assert!(!patch.contains(SECRET_VALUE));
    assert!(!format!("{a:?}").contains(SECRET_VALUE));
}

#[test]
fn lines_inside_the_include_block_are_never_eligible() {
    let es = entries(&[("EDITOR", "vim")]);
    // A hand-added managed line between the markers (not ours to remove).
    let tampered = block().replace(
        &format!("if [ -f \"$HOME/{}\" ]; then", envmap::CANONICAL_REL),
        &format!(
            "EDITOR=vim\nif [ -f \"$HOME/{}\" ]; then",
            envmap::CANONICAL_REL
        ),
    );
    let body = format!("export EDITOR=vim\n{tampered}");
    let tmp = home_with(&es, &[(".bashrc", &body)]);
    let a = assess_move(tmp.path(), &es).expect("assess");
    assert_eq!(a.eligible.len(), 1, "only the top-level line is eligible");
    assert!(
        a.ineligible
            .iter()
            .any(|i| i.reason.contains("inside the managed include block")),
        "{:?}",
        a.ineligible
    );
    let patch = build_patch(&a, 1_700_000_000);
    assert_eq!(patch.matches("@@ ").count(), 1);
}

#[test]
fn matching_line_without_an_include_block_stays_put() {
    let es = entries(&[("EDITOR", "vim")]);
    let tmp = home_with(&es, &[(".bashrc", "export EDITOR=vim\n")]);
    let a = assess_move(tmp.path(), &es).expect("assess");
    assert!(a.eligible.is_empty());
    assert!(
        a.ineligible
            .iter()
            .any(|i| i.reason.contains("include block not present")),
        "{:?}",
        a.ineligible
    );
    // Zero eligible is still success (NoOp), not an error.
    assert!(build_patch(&a, 1).contains("nothing to tombstone"));
}

#[test]
fn missing_or_stale_canonical_is_a_precondition_error() {
    let es = entries(&[("EDITOR", "vim")]);
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(".bashrc"), "export EDITOR=vim\n").unwrap();

    let err = assess_move(tmp.path(), &es).expect_err("missing canonical must fail");
    assert!(matches!(err, MoveError::Precondition(_)), "{err:?}");

    // Stale: canonical on disk does not match the profile.
    let dir = tmp.path().join(".config/configctl");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("env.sh"), "EDITOR=nano\n").unwrap();
    let err = assess_move(tmp.path(), &es).expect_err("stale canonical must fail");
    assert!(matches!(err, MoveError::Precondition(_)), "{err:?}");
}

#[test]
fn secret_like_profile_literals_are_a_hard_error() {
    let es = entries(&[("EDITOR", "vim"), ("DB_PASSWORD", "hunter2")]);
    let tmp = tempfile::tempdir().unwrap();
    let err = assess_move(tmp.path(), &es).expect_err("secret trip must fail");
    assert_eq!(
        err,
        MoveError::SecretTrip("DB_PASSWORD".into()),
        "names the variable, never the value"
    );
    assert!(!err.to_string().contains("hunter2"));
}

#[test]
fn patch_is_deterministic_for_a_fixed_timestamp() {
    let es = entries(&[("EDITOR", "vim"), ("LANG", "en_US.UTF-8")]);
    let body = format!("export EDITOR=vim\nexport LANG=en_US.UTF-8\n{}", block());
    let tmp = home_with(&es, &[(".bashrc", &body)]);
    let a = assess_move(tmp.path(), &es).expect("assess");
    assert_eq!(a.eligible.len(), 2);
    assert_eq!(build_patch(&a, 42), build_patch(&a, 42));
    assert_ne!(build_patch(&a, 42), build_patch(&a, 43));
    // Adjacent lines get correctly offset +line numbers (-1/+2 each).
    let patch = build_patch(&a, 42);
    assert!(patch.contains("@@ -1,1 +1,2 @@"), "{patch}");
    assert!(patch.contains("@@ -2,1 +3,2 @@"), "{patch}");
    assert!(patch.contains("# configctl-move @42 UTC: EDITOR consolidated to"));
}

#[test]
fn patch_applies_cleanly_with_patch_dry_run() {
    let es = entries(&[("EDITOR", "vim"), ("LANG", "en_US.UTF-8")]);
    let body = format!("export EDITOR=vim\nexport LANG=en_US.UTF-8\n{}", block());
    let tmp = home_with(&es, &[(".bashrc", &body)]);
    let home = tmp.path();
    let a = assess_move(home, &es).expect("assess");
    let patch = build_patch(&a, 1_700_000_000);
    let patch_file = home.join("move.patch");
    std::fs::write(&patch_file, patch.as_bytes()).unwrap();

    let status = std::process::Command::new("patch")
        .args(["--dry-run", "-p0", "--silent"])
        .current_dir(home)
        .stdin(std::fs::File::open(&patch_file).unwrap())
        .status()
        .expect("patch binary must exist");
    assert!(
        status.success(),
        "patch --dry-run -p0 must accept the emitted diff"
    );
}

#[test]
fn adversarial_files_fail_closed() {
    let es = entries(&[("EDITOR", "vim")]);
    let tmp = tempfile::tempdir().unwrap();
    let home: &Path = tmp.path();
    let dir = home.join(".config/configctl");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("env.sh"),
        envmap::canonical_env_file(&es).as_bytes(),
    )
    .unwrap();

    // CRLF line endings.
    std::fs::write(home.join(".bashrc"), b"export EDITOR=vim\r\n").unwrap();
    // Spoofed markers: two blocks.
    let two = format!("{}\n{}", block(), block());
    std::fs::write(home.join(".profile"), two.as_bytes()).unwrap();
    // Partial block: begin without end.
    std::fs::write(
        home.join(".zshrc"),
        format!("export EDITOR=vim\n{}", envmap::INCLUDE_BEGIN).as_bytes(),
    )
    .unwrap();
    // Oversize file.
    let big = vec![b'#'; MAX_RC_BYTES as usize + 1];
    std::fs::write(home.join(".zshenv"), &big).unwrap();
    // Symlinked rc file.
    std::fs::write(home.join(".bash_profile"), "export EDITOR=vim\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(home.join(".bash_profile"), home.join(".bashrc.link_target"))
        .unwrap();
    // Point .bash_profile at a symlink instead: replace with symlink to a real file.
    std::fs::remove_file(home.join(".bash_profile")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(home.join(".bashrc"), home.join(".bash_profile")).unwrap();

    let a = assess_move(home, &es).expect("assessment itself still succeeds");
    assert!(a.eligible.is_empty(), "{:?}", a.eligible);
    for want in [".bashrc", ".profile", ".zshrc", ".zshenv", ".bash_profile"] {
        let f = a
            .files
            .iter()
            .find(|f| f.rel == want)
            .unwrap_or_else(|| panic!("{want} assessed"));
        assert!(f.refused.is_some(), "{want} must be refused: {f:?}");
    }
    let patch = build_patch(&a, 1);
    assert!(patch.contains("nothing to tombstone"));
}

#[test]
fn assessment_covers_all_participating_rc_files() {
    let es = entries(&[("EDITOR", "vim")]);
    let body = |extra: &str| format!("export EDITOR=vim\n{extra}{}", block());
    let tmp = home_with(
        &es,
        &[
            (".bashrc", &body("")),
            (".bash_profile", &body("")),
            (".profile", &body("")),
            (".zshrc", &body("")),
            (".zshenv", &body("")),
        ],
    );
    let a = assess_move(tmp.path(), &es).expect("assess");
    assert_eq!(a.eligible.len(), 5);
    let mut files: Vec<&str> = a.eligible.iter().map(|e| e.rel.as_str()).collect();
    files.sort();
    assert_eq!(
        files,
        vec![".bash_profile", ".bashrc", ".profile", ".zshenv", ".zshrc"]
    );
    // Every assessed file carries its content hash for the TOCTOU note.
    assert!(a.files.iter().all(|f| f.hash.is_some()));
    let hashes: BTreeMap<String, String> = a
        .files
        .iter()
        .filter_map(|f| f.hash.clone().map(|h| (f.file.clone(), h)))
        .collect();
    assert_eq!(hashes.len(), 5);
}

#[test]
fn untouched_home_dir_is_not_an_error() {
    let es = entries(&[("EDITOR", "vim")]);
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join(".config/configctl");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("env.sh"),
        envmap::canonical_env_file(&es).as_bytes(),
    )
    .unwrap();
    let a = assess_move(tmp.path(), &es).expect("assess");
    assert!(a.eligible.is_empty() && a.files.is_empty());
    assert!(build_patch(&a, 1).contains("nothing to tombstone"));
}

fn _unused_pathbuf(_p: &PathBuf) {}
