//! `dnf` (Fedora/RHEL) + `pacman` (Arch) provider tests.
//!
//! Mirrors the apt test pattern: fake `CommandRunner`, disposable fixtures,
//! exact argv assertions (`sudo -n` + fixed argv, no shell). Live subprocess
//! use is limited to one negative probe test that SKIPs with a reason when
//! the expectation does not apply (never fails on absent tools).

use configctl_core::apply::{apply_plan, ApplyOptions};
use configctl_core::command::{CommandOutput, FakeCommandRunner, StdCommandRunner};
use configctl_core::observe::{observe_with_os, ObservedState};
use configctl_core::package_managers::{
    family_matches, parse_os_release, read_os_release, DnfProvider, NativeFamily, OsRelease,
    PacmanProvider,
};
use configctl_core::plan::{self, OperationKind, RollbackSupport};
use configctl_core::profile::Profile;
use std::collections::{BTreeMap, BTreeSet};

fn ok_out(stdout: &str) -> CommandOutput {
    CommandOutput {
        status: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    }
}

fn fail_out() -> CommandOutput {
    CommandOutput {
        status: Some(1),
        stdout: String::new(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    }
}

// ---------------------------------------------------------------------------
// os-release fixtures (minimal but faithful excerpts)
// ---------------------------------------------------------------------------

const FEDORA_OS: &str = r#"
NAME="Fedora Linux"
VERSION="40 (Workstation Edition)"
ID=fedora
VERSION_ID=40
PLATFORM_ID="platform:f40"
PRETTY_NAME="Fedora Linux 40 (Workstation Edition)"
"#;

const RHEL_OS: &str = r#"
NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
"#;

const CENTOS_STREAM_OS: &str = r#"
NAME="CentOS Stream"
VERSION="9"
ID="centos"
ID_LIKE="rhel centos fedora"
VERSION_ID="9"
PLATFORM_ID="platform:el9-centos"
PRETTY_NAME="CentOS Stream 9"
"#;

const ROCKY_OS: &str = r#"
NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
"#;

const ARCH_OS: &str = r#"
NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
"#;

const MANJARO_OS: &str = r#"
NAME="Manjaro Linux"
PRETTY_NAME="Manjaro Linux"
ID=manjaro
ID_LIKE=arch
BUILD_ID=rolling
"#;

const UBUNTU_OS: &str = r#"
PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
"#;

const DEBIAN_OS: &str = r#"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
"#;

#[test]
fn os_release_parses_id_and_id_like() {
    let fedora = parse_os_release(FEDORA_OS);
    assert_eq!(fedora.id, "fedora");
    assert!(fedora.id_like.is_empty());

    let centos = parse_os_release(CENTOS_STREAM_OS);
    assert_eq!(centos.id, "centos");
    assert_eq!(centos.id_like, vec!["rhel", "centos", "fedora"]);

    let ubuntu = parse_os_release(UBUNTU_OS);
    assert_eq!(ubuntu.id, "ubuntu");
    assert_eq!(ubuntu.id_like, vec!["debian"]);

    // Comments, blanks, and quoted values never leak through.
    let weird = parse_os_release("# comment\n\nID=\"Arch\"\nID_LIKE='arch  '\nFOO=bar\n");
    assert_eq!(weird.id, "arch");
    assert_eq!(weird.id_like, vec!["arch"]);

    // Garbage yields empty identity (never guessed).
    let empty = parse_os_release("GARBAGE\n");
    assert_eq!(empty, OsRelease::default());
}

#[test]
fn distro_family_matrix() {
    let fedora = |text: &str| family_matches(&parse_os_release(text), NativeFamily::Fedora);
    let arch = |text: &str| family_matches(&parse_os_release(text), NativeFamily::Arch);
    assert!(fedora(FEDORA_OS));
    assert!(fedora(RHEL_OS));
    assert!(fedora(CENTOS_STREAM_OS));
    assert!(fedora(ROCKY_OS));
    assert!(!fedora(ARCH_OS));
    assert!(!fedora(UBUNTU_OS));
    assert!(!fedora(DEBIAN_OS));
    assert!(arch(ARCH_OS));
    assert!(arch(MANJARO_OS));
    assert!(!arch(FEDORA_OS));
    assert!(!arch(UBUNTU_OS));
    // Unknown distros match nothing (fail closed).
    assert!(!fedora("ID=mystery\n"));
    assert!(!arch("ID=mystery\n"));
}

// ---------------------------------------------------------------------------
// Probe matrix: distro × binary present/absent
// ---------------------------------------------------------------------------

#[test]
fn probe_matrix_distro_times_binary() {
    let fedora = parse_os_release(FEDORA_OS);
    let rhel = parse_os_release(RHEL_OS);
    let rocky = parse_os_release(ROCKY_OS);
    let arch = parse_os_release(ARCH_OS);
    let manjaro = parse_os_release(MANJARO_OS);
    let ubuntu = parse_os_release(UBUNTU_OS);

    // Matching distro + binary → available.
    assert!(DnfProvider::probe_with(Some(&fedora), true).is_ok());
    assert!(DnfProvider::probe_with(Some(&rhel), true).is_ok());
    assert!(DnfProvider::probe_with(Some(&rocky), true).is_ok());
    assert!(PacmanProvider::probe_with(Some(&arch), true).is_ok());
    assert!(PacmanProvider::probe_with(Some(&manjaro), true).is_ok());

    // Matching distro, binary absent → unavailable (never a silent skip).
    assert!(DnfProvider::probe_with(Some(&fedora), false).is_err());
    assert!(PacmanProvider::probe_with(Some(&arch), false).is_err());

    // Wrong distro, binary present → still unavailable (distro gates).
    assert!(DnfProvider::probe_with(Some(&ubuntu), true).is_err());
    assert!(DnfProvider::probe_with(Some(&arch), true).is_err());
    assert!(PacmanProvider::probe_with(Some(&ubuntu), true).is_err());
    assert!(PacmanProvider::probe_with(Some(&fedora), true).is_err());

    // Unknown distro → unavailable for both.
    assert!(DnfProvider::probe_with(None, true).is_err());
    assert!(PacmanProvider::probe_with(None, true).is_err());
    assert!(DnfProvider::probe_with(None, false).is_err());
    assert!(PacmanProvider::probe_with(None, false).is_err());
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn capabilities_are_honest() {
    assert!(DnfProvider::REQUIRES_ELEVATION);
    assert!(DnfProvider::TOUCHES_NETWORK);
    assert!(!DnfProvider::SUPPORTS_ROLLBACK);
    assert!(PacmanProvider::REQUIRES_ELEVATION);
    assert!(PacmanProvider::TOUCHES_NETWORK);
    assert!(!PacmanProvider::SUPPORTS_ROLLBACK);
    assert_eq!(DnfProvider::ID, "dnf");
    assert_eq!(PacmanProvider::ID, "pacman");
}

// ---------------------------------------------------------------------------
// Parsing golden outputs (epochs, arch suffixes, hostile lines)
// ---------------------------------------------------------------------------

#[test]
fn rpm_parse_preserves_epochs_and_arch() {
    let out = DnfProvider::parse_list(
        "git\t1:2.43.0-1.fc40\tx86_64\nNetworkManager\t1:1.46.0-1.fc40\tx86_64\nkernel\t6.8.5-301.fc40\tx86_64\ncurl\t8.5.0-1.fc40\tnoarch\n",
    );
    assert_eq!(out.len(), 4);
    let git = out.iter().find(|p| p.name == "git").unwrap();
    assert_eq!(git.version, "1:2.43.0-1.fc40");
    assert_eq!(git.architecture.as_deref(), Some("x86_64"));
    // Uppercase RPM names survive validation.
    assert!(out.iter().any(|p| p.name == "NetworkManager"));
    // Sorted, deduped.
    let names: Vec<&str> = out.iter().map(|p| p.name.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn rpm_parse_skips_malformed_and_hostile_lines() {
    let out = DnfProvider::parse_list(
        "good\t1.0-1.fc40\tx86_64\nmalformed-line\n$(evil)\t1.0\tx86_64\n../../etc\t1.0\tx86_64\n\t\n; rm -rf\t1.0\tx86_64\nempty-ver\t\t\n",
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "good");
}

#[test]
fn pacman_parse_golden_and_rejects_extras() {
    let out = PacmanProvider::parse_list(
        "ripgrep 14.1.0-1\nlinux 6.8.5.arch1-1\nwine 1:9.0-1\nthree fields here\nlonely\n\n$(evil) 1.0\n",
    );
    assert_eq!(out.len(), 3);
    assert!(out
        .iter()
        .any(|p| p.name == "wine" && p.version == "1:9.0-1"));
    assert!(out.iter().all(|p| p.architecture.is_none()));
}

#[test]
fn list_argv_is_pinned_and_shell_free() {
    let dnf = DnfProvider::list_request();
    assert_eq!(dnf.program.to_string_lossy(), "rpm");
    assert_eq!(
        dnf.args,
        vec!["-qa", "--queryformat", "%{NAME}\t%{EVR}\t%{ARCH}\n"]
    );
    let pacman = PacmanProvider::list_request();
    assert_eq!(pacman.program.to_string_lossy(), "pacman");
    assert_eq!(pacman.args, vec!["-Q"]);
    for req in [&dnf, &pacman] {
        for a in &req.args {
            assert!(!a.contains(';') && !a.contains('|') && !a.contains("$("));
        }
    }
}

#[test]
fn native_name_grammar_accepts_rpm_shapes_rejects_shell() {
    use configctl_core::paths::validate_native_package_name as v;
    assert!(v("git").is_ok());
    assert!(v("NetworkManager").is_ok());
    assert!(v("python3-pip").is_ok());
    assert!(v("perl-IO-Socket-SSL").is_ok());
    assert!(v("1password").is_ok());
    assert!(v("g++").is_ok());
    assert!(v("foo:bar").is_ok());
    assert!(v("").is_err());
    assert!(v("$(evil)").is_err());
    assert!(v("a;b").is_err());
    assert!(v("a|b").is_err());
    assert!(v("../../etc").is_err());
    assert!(v("-leading").is_err());
    assert!(v("has space").is_err());
    assert!(v("has/slash").is_err());
}

// ---------------------------------------------------------------------------
// Capture via fake runner (incl. unavailable path + argv exactness)
// ---------------------------------------------------------------------------

#[test]
fn dnf_capture_uses_allowlist_and_fixed_argv() {
    let runner = FakeCommandRunner::new();
    runner.queue(ok_out(
        "git\t1:2.43.0-1.fc40\tx86_64\ncurl\t8.5.0-1.fc40\tx86_64\nkernel\t6.8.5-301.fc40\tx86_64\nbad;name\t1.0\tx86_64\n",
    ));
    let cap = DnfProvider::capture(&runner);
    assert!(!cap.unavailable);
    assert_eq!(cap.installed_total, 3);
    // kernel excluded by policy; bad name rejected by validation.
    assert_eq!(cap.selected.len(), 2);
    let calls = runner.recorded();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program.to_string_lossy(), "rpm");
}

#[test]
fn pacman_capture_uses_allowlist_and_fixed_argv() {
    let runner = FakeCommandRunner::new();
    runner.queue(ok_out("git 2.43.0-1\ncurl 8.5.0-1\nlinux 6.8.5.arch1-1\n"));
    let cap = PacmanProvider::capture(&runner);
    assert!(!cap.unavailable);
    assert_eq!(cap.installed_total, 3);
    assert_eq!(cap.selected.len(), 2);
    let calls = runner.recorded();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program.to_string_lossy(), "pacman");
    assert_eq!(calls[0].args, vec!["-Q"]);
}

#[test]
fn native_capture_unavailable_when_binary_missing() {
    let runner = FakeCommandRunner::new();
    runner.queue(fail_out());
    assert!(DnfProvider::capture(&runner).unavailable);
    let runner = FakeCommandRunner::new();
    runner.queue(fail_out());
    assert!(PacmanProvider::capture(&runner).unavailable);
}

// ---------------------------------------------------------------------------
// Observe: distro-gated, zero subprocess calls off-platform
// ---------------------------------------------------------------------------

#[test]
fn observe_marks_unavailable_off_platform_without_subprocess() {
    let runner = FakeCommandRunner::new();
    let ubuntu = parse_os_release(UBUNTU_OS);
    let st = observe_with_os(
        &runner,
        std::path::Path::new("/tmp"),
        &[],
        &["git".to_string()],
        &["ripgrep".to_string()],
        Some(&ubuntu),
        &[],
        false,
        &[],
        &[],
        &|_| None,
        &[],
    );
    assert!(st.dnf_unavailable);
    assert!(st.pacman_unavailable);
    assert!(st.dnf_packages.is_empty());
    assert!(st.pacman_packages.is_empty());
    // Only the apt probe ran (dnf/pacman gated out before any subprocess).
    let calls = runner.recorded();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program.to_string_lossy(), "dpkg-query");
}

#[test]
fn observe_lists_wanted_names_on_native_distro() {
    let runner = FakeCommandRunner::new();
    // observe always probes apt first, then dnf (version + list).
    runner.queue(ok_out(""));
    // dnf --version (binary present), then rpm -qa.
    runner.queue(ok_out("dnf version 4.18.0\n"));
    runner.queue(ok_out(
        "git\t1:2.43.0-1.fc40\tx86_64\ncurl\t8.5.0-1.fc40\tx86_64\n",
    ));
    // pacman: wrong distro (fedora) → unavailable, no calls.
    let fedora = parse_os_release(FEDORA_OS);
    let st = observe_with_os(
        &runner,
        std::path::Path::new("/tmp"),
        &[],
        &["git".to_string()],
        &["ripgrep".to_string()],
        Some(&fedora),
        &[],
        false,
        &[],
        &[],
        &|_| None,
        &[],
    );
    assert!(!st.dnf_unavailable);
    assert_eq!(
        st.dnf_packages.get("git").map(String::as_str),
        Some("1:2.43.0-1.fc40")
    );
    assert!(st.pacman_unavailable);
    let calls = runner.recorded();
    assert_eq!(calls.len(), 3); // dpkg-query + dnf --version + rpm -qa
    assert_eq!(calls[1].program.to_string_lossy(), "dnf");
    assert_eq!(calls[1].args, vec!["--version"]);
    assert_eq!(calls[2].program.to_string_lossy(), "rpm");
}

#[test]
fn observe_skips_native_managers_when_nothing_wanted() {
    let runner = FakeCommandRunner::new();
    let fedora = parse_os_release(FEDORA_OS);
    let st = observe_with_os(
        &runner,
        std::path::Path::new("/tmp"),
        &[],
        &[],
        &[],
        Some(&fedora),
        &[],
        false,
        &[],
        &[],
        &|_| None,
        &[],
    );
    assert!(!st.dnf_unavailable);
    assert!(!st.pacman_unavailable);
    // Only the apt probe ran.
    assert_eq!(runner.recorded().len(), 1);
}

// ---------------------------------------------------------------------------
// Plan + verify mirror apt exactly
// ---------------------------------------------------------------------------

fn loaded_with(p: &Profile) -> configctl_core::profile_load::LoadedProfile {
    let payload = BTreeMap::new();
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

#[test]
fn plan_installs_via_dnf_and_pacman() {
    let mut p = Profile::new("work");
    p.packages.dnf = vec!["ripgrep".into()];
    p.packages.pacman = vec!["jq".into()];
    let loaded = loaded_with(&p);
    let st = ObservedState::default();
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "a", 1);
    let dnf_op = plan
        .operations
        .iter()
        .find(|o| o.provider == "dnf")
        .expect("dnf op");
    assert_eq!(dnf_op.kind, OperationKind::PackageInstall);
    assert_eq!(dnf_op.summary, "package ripgrep: install via dnf");
    assert_eq!(dnf_op.rollback, RollbackSupport::Unsupported);
    let pacman_op = plan
        .operations
        .iter()
        .find(|o| o.provider == "pacman")
        .expect("pacman op");
    assert_eq!(pacman_op.summary, "package jq: install via pacman");
    assert_eq!(pacman_op.rollback, RollbackSupport::Unsupported);
}

#[test]
fn plan_marks_unavailable_managers_unsupported() {
    let mut p = Profile::new("work");
    p.packages.dnf = vec!["ripgrep".into()];
    p.packages.pacman = vec!["jq".into()];
    let loaded = loaded_with(&p);
    let st = ObservedState {
        dnf_unavailable: true,
        pacman_unavailable: true,
        ..Default::default()
    };
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "a", 1);
    assert_eq!(plan.operations.len(), 2);
    assert!(plan
        .operations
        .iter()
        .all(|o| o.kind == OperationKind::Unsupported));
    assert!(plan
        .warnings
        .iter()
        .any(|w| w.code == "packages_unavailable"));
}

#[test]
fn plan_reports_native_lock_drift_without_downgrade() {
    use configctl_core::profile::{PackagesLock, SCHEMA_VERSION};
    let mut p = Profile::new("work");
    p.packages.dnf = vec!["ripgrep".into()];
    let mut loaded = loaded_with(&p);
    loaded.lock = Some(PackagesLock {
        schema_version: SCHEMA_VERSION,
        apt: Default::default(),
        dnf: BTreeMap::from([("ripgrep".into(), "14.1.0-1.fc40".into())]),
        pacman: Default::default(),
        other: Default::default(),
    });
    let mut st = ObservedState::default();
    st.dnf_packages
        .insert("ripgrep".into(), "14.0-1.fc40".into());
    let plan = plan::build_plan(&loaded, &st, &BTreeSet::new(), "a", 1);
    assert!(plan.operations.iter().any(|o| {
        o.kind == OperationKind::PackageVersionMismatch
            && o.provider == "dnf"
            && o.rollback == RollbackSupport::Unsupported
    }));
    assert!(plan
        .warnings
        .iter()
        .any(|w| w.code == "package_version_drift"));
}

#[test]
fn verify_covers_native_managers() {
    let mut p = Profile::new("work");
    p.packages.dnf = vec!["ripgrep".into(), "missing-tool".into()];
    p.packages.pacman = vec!["jq".into()];
    let loaded = loaded_with(&p);
    let mut st = ObservedState::default();
    st.dnf_packages
        .insert("ripgrep".into(), "14.1.0-1.fc40".into());
    let report = configctl_core::verify::verify(&loaded, &st);
    let status = |target: &str| {
        report
            .results
            .iter()
            .find(|r| r.target == target)
            .map(|r| r.status)
    };
    use configctl_core::verify::CheckStatus as S;
    assert_eq!(status("ripgrep"), Some(S::Match));
    assert_eq!(status("missing-tool"), Some(S::Missing));
    assert_eq!(status("jq"), Some(S::Missing));

    // Unavailable managers verify Unsupported (never silently skipped).
    let st = ObservedState {
        dnf_unavailable: true,
        pacman_unavailable: true,
        ..Default::default()
    };
    let report = configctl_core::verify::verify(&loaded, &st);
    assert!(report.results.iter().any(|r| r.status == S::Unsupported));
}

// ---------------------------------------------------------------------------
// Apply: elevation argv exactness, precheck/postcheck, privilege honesty
// ---------------------------------------------------------------------------

struct Fx {
    _tmp: tempfile::TempDir,
    home: std::path::PathBuf,
    bundle: std::path::PathBuf,
    state: std::path::PathBuf,
}

fn setup(extra_toml: &str) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let bundle = tmp.path().join("work");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(bundle.join("files")).unwrap();
    std::fs::write(
        bundle.join("profile.toml"),
        format!("schema_version = 1\nname = \"work\"\n{extra_toml}"),
    )
    .unwrap();
    Fx {
        _tmp: tmp,
        home,
        bundle,
        state,
    }
}

fn plan_for(fx: &Fx, st: &ObservedState, plan_id: &str) {
    let l = configctl_core::profile_load::load_profile_dir(&fx.bundle).expect("load bundle");
    let owned =
        configctl_core::state::ownership_for_profile(&fx.state, &l.identity).unwrap_or_default();
    let p = plan::build_plan(&l, st, &owned, plan_id, 1000);
    configctl_core::state::save_plan(&fx.state, &p, &l.dir).unwrap();
}

fn yes(_: &configctl_core::plan::Plan) -> bool {
    true
}

#[test]
fn dnf_install_argv_is_fixed_and_elevated() {
    let fx = setup("\n[packages]\ndnf = [\"ripgrep\"]\n");
    let runner = FakeCommandRunner::new();
    // precheck `rpm -q`: not installed (exit 1).
    runner.queue(fail_out());
    // execute sudo: ok.
    runner.queue(ok_out("done\n"));
    // postcheck `rpm -q`: installed.
    runner.queue(ok_out("ripgrep-14.1.0-1.fc40.x86_64\n"));
    plan_for(&fx, &ObservedState::default(), "p-dnf");
    apply_plan(
        &fx.state,
        "p-dnf",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("dnf apply");
    let calls = runner.recorded();
    assert_eq!(calls.len(), 3);
    // Precheck probes installed state via fixed argv (no shell, no sudo).
    assert_eq!(calls[0].program.to_string_lossy(), "rpm");
    assert_eq!(calls[0].args, vec!["-q", "ripgrep"]);
    // Elevation is exactly `sudo -n` + fixed argv.
    assert_eq!(calls[1].program.to_string_lossy(), "sudo");
    assert_eq!(calls[1].args, vec!["-n", "dnf", "install", "-y", "ripgrep"]);
    for c in &calls {
        let blob = format!("{:?} {:?}", c.program, c.args);
        assert!(!blob.contains('|') && !blob.contains(';') && !blob.contains("$("));
    }
}

#[test]
fn pacman_install_argv_is_fixed_and_elevated() {
    let fx = setup("\n[packages]\npacman = [\"ripgrep\"]\n");
    let runner = FakeCommandRunner::new();
    // precheck `pacman -Q`: not installed.
    runner.queue(fail_out());
    // execute sudo: ok.
    runner.queue(ok_out("done\n"));
    // postcheck `pacman -Q`: installed.
    runner.queue(ok_out("ripgrep 14.1.0-1\n"));
    plan_for(&fx, &ObservedState::default(), "p-pacman");
    apply_plan(
        &fx.state,
        "p-pacman",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("pacman apply");
    let calls = runner.recorded();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].program.to_string_lossy(), "pacman");
    assert_eq!(calls[0].args, vec!["-Q", "ripgrep"]);
    assert_eq!(calls[1].program.to_string_lossy(), "sudo");
    assert_eq!(
        calls[1].args,
        vec!["-n", "pacman", "-S", "--noconfirm", "ripgrep"]
    );
}

#[test]
fn dnf_privilege_failure_is_honest() {
    let fx = setup("\n[packages]\ndnf = [\"ripgrep\"]\n");
    let runner = FakeCommandRunner::new();
    runner.queue(fail_out()); // precheck: not installed
    runner.queue(CommandOutput {
        status: Some(1),
        stdout: String::new(),
        stderr: "sudo: a password is required\n".into(),
        truncated: false,
        timed_out: false,
    });
    plan_for(&fx, &ObservedState::default(), "p-dnf-priv");
    let err = apply_plan(
        &fx.state,
        "p-dnf-priv",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(
        matches!(err, configctl_core::apply::ApplyError::Privilege(_)),
        "got {err:?}"
    );
}

#[test]
fn native_precheck_noop_when_already_installed() {
    let fx = setup("\n[packages]\ndnf = [\"ripgrep\"]\n");
    let runner = FakeCommandRunner::new();
    // precheck `rpm -q`: already installed → noop (no sudo call).
    runner.queue(ok_out("ripgrep-14.1.0-1.fc40.x86_64\n"));
    plan_for(&fx, &ObservedState::default(), "p-dnf-noop");
    let rep = apply_plan(
        &fx.state,
        "p-dnf-noop",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("noop apply");
    assert!(rep.executed.is_empty());
    assert_eq!(rep.noop, vec!["op-0001".to_string()]);
    assert!(runner
        .recorded()
        .iter()
        .all(|c| { c.program.to_string_lossy() != "sudo" }));
}

#[test]
fn unknown_package_provider_fails_closed() {
    // A hand-edited plan steering PackageInstall at an unknown provider
    // must fail closed (exit 7 class), never run.
    let fx = setup("\n[packages]\napt = [\"ripgrep\"]\n");
    let runner = FakeCommandRunner::new();
    let l = configctl_core::profile_load::load_profile_dir(&fx.bundle).expect("load");
    let owned =
        configctl_core::state::ownership_for_profile(&fx.state, &l.identity).unwrap_or_default();
    let mut p = plan::build_plan(&l, &ObservedState::default(), &owned, "p-evil", 1000);
    for op in p.operations.iter_mut() {
        if op.kind == OperationKind::PackageInstall {
            op.provider = "brew".into();
        }
    }
    p.plan_hash = plan::compute_plan_hash(&p);
    configctl_core::state::save_plan(&fx.state, &p, &l.dir).unwrap();
    let err = apply_plan(
        &fx.state,
        "p-evil",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            configctl_core::apply::ApplyError::ProviderUnavailable(_)
        ),
        "got {err:?}"
    );
    // Nothing ran: no subprocess calls at all.
    assert!(runner.recorded().is_empty());
}

// ---------------------------------------------------------------------------
// Rollback: report-only hints mirror apt
// ---------------------------------------------------------------------------

#[test]
fn rollback_hints_are_report_only_per_manager() {
    assert_eq!(
        DnfProvider::rollback_hint("ripgrep"),
        "package ripgrep: installed by apply; v1 never auto-removes (manual: dnf remove ripgrep)"
    );
    assert_eq!(
        PacmanProvider::rollback_hint("ripgrep"),
        "package ripgrep: installed by apply; v1 never auto-removes (manual: pacman -R ripgrep)"
    );
    // Plan text carries Unsupported (the "not automatically revertible"
    // disclosure, exactly like apt).
    let mut p = Profile::new("work");
    p.packages.dnf = vec!["ripgrep".into()];
    let loaded = loaded_with(&p);
    let plan = plan::build_plan(&loaded, &ObservedState::default(), &BTreeSet::new(), "a", 1);
    assert!(plan
        .operations
        .iter()
        .all(|o| { o.rollback == RollbackSupport::Unsupported }));
}

#[test]
fn rollback_lists_native_packages_for_manual_removal() {
    let fx = setup("\n[packages]\ndnf = [\"ripgrep\"]\n");
    let runner = FakeCommandRunner::new();
    runner.queue(fail_out());
    runner.queue(ok_out("done\n"));
    runner.queue(ok_out("ripgrep-14.1.0-1.fc40.x86_64\n"));
    plan_for(&fx, &ObservedState::default(), "rb-dnf");
    apply_plan(
        &fx.state,
        "rb-dnf",
        &fx.home,
        &runner,
        &ApplyOptions {
            yes: true,
            ..Default::default()
        },
        &yes,
    )
    .expect("apply");
    let report = configctl_core::rollback::rollback_plan(
        &fx.state,
        "rb-dnf",
        &fx.home,
        &configctl_core::rollback::RollbackOptions {
            yes: true,
            dry_run: true,
        },
        &|_| true,
    )
    .expect("rollback preview");
    assert!(report.restored.is_empty());
    assert!(report
        .manual
        .iter()
        .any(|m| m.contains("dnf remove ripgrep")));
    assert!(!report.manual.iter().any(|m| m.contains("apt remove")));
}

// ---------------------------------------------------------------------------
// Schema: dnf/pacman first-class, unknown managers rejected
// ---------------------------------------------------------------------------

#[test]
fn schema_accepts_dnf_and_pacman_rejects_unknown_managers() {
    let p = Profile::from_toml(
        "schema_version = 1\nname = \"work\"\n\n[packages]\napt = [\"git\"]\ndnf = [\"NetworkManager\"]\npacman = [\"ripgrep\"]\n",
    )
    .expect("dnf/pacman parse");
    assert!(p.validate().is_empty());
    assert_eq!(p.packages.dnf, vec!["NetworkManager".to_string()]);
    assert_eq!(p.packages.pacman, vec!["ripgrep".to_string()]);
    // Canonical form round-trips.
    let toml = p.to_toml().expect("serialize");
    let back = Profile::from_toml(&toml).expect("deserialize");
    assert_eq!(back.packages.dnf, p.packages.dnf);

    // Unknown top-level managers are rejected (DEFERRED ground rule §8.2:
    // never silently ignored) — `apk` stays deferred.
    let err =
        Profile::from_toml("schema_version = 1\nname = \"work\"\n\n[packages]\napk = [\"git\"]\n")
            .expect_err("apk must not parse");
    assert!(err.contains("apk"), "{err:?}");

    // Invalid native names fail validation.
    let mut bad = Profile::new("bad");
    bad.packages.dnf = vec!["$(evil)".into()];
    assert!(!bad.validate().is_empty());
    let mut dup = Profile::new("dup");
    dup.packages.pacman = vec!["jq".into(), "jq".into()];
    assert!(dup.validate().iter().any(|e| e.contains("duplicate")));
}

// ---------------------------------------------------------------------------
// Live negative probe (Ubuntu): real runner, no fakes
// ---------------------------------------------------------------------------

#[test]
fn live_probe_is_unavailable_on_non_native_distros() {
    let live = read_os_release();
    let native_here = live.as_ref().map(|os| {
        family_matches(os, NativeFamily::Fedora) || family_matches(os, NativeFamily::Arch)
    });
    if native_here.unwrap_or(false) {
        eprintln!("SKIP: native distro here; negative expectation does not apply");
        return;
    }
    // This machine is Ubuntu (or otherwise non-native): both providers must
    // report Unavailable through the real runner (distro gate, no fakes).
    let runner = StdCommandRunner::new();
    let dnf_err = DnfProvider::probe(&runner).expect_err("dnf must be unavailable here");
    let pacman_err = PacmanProvider::probe(&runner).expect_err("pacman must be unavailable here");
    assert!(dnf_err.contains("dnf"), "{dnf_err:?}");
    assert!(pacman_err.contains("pacman"), "{pacman_err:?}");
    // And the failure is the distro gate, not a missing binary: even with
    // the binary present the platform would not match.
    assert!(DnfProvider::probe_with(live.as_ref(), true).is_err());
    assert!(PacmanProvider::probe_with(live.as_ref(), true).is_err());
}
