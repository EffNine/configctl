//! P5 tests: services, environment, hardware, credentials, .env depth.

use configctl_core::command::{CommandOutput, FakeCommandRunner};
use configctl_core::governor::{GovernorBudgets, ResourceGovernor};
use configctl_discovery::credentials::collect_credentials;
use configctl_discovery::environment::collect_environment;
use configctl_discovery::hardware::collect_hardware;
use configctl_discovery::scanner::{ScanOptions, Scanner};
use configctl_discovery::services::collect_services;
use std::path::Path;
use std::sync::Arc;

fn ok(stdout: &str) -> CommandOutput {
    CommandOutput {
        status: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    }
}

fn governor() -> Arc<ResourceGovernor> {
    ResourceGovernor::new(GovernorBudgets::default())
}

#[test]
fn systemd_user_units_parsed_with_states() {
    let runner = FakeCommandRunner::new();
    // user list-units
    runner.queue(ok(
        "syncthing.service loaded active running Syncthing\nfoo.timer loaded active waiting x\nbad;unit.service loaded active running evil\n",
    ));
    // user list-unit-files
    runner.queue(ok("syncthing.service enabled\nfoo.service disabled\n"));
    // detail probes run in sorted unit order: foo.service first, then syncthing.
    runner.queue(ok("FragmentPath=\nDropInPaths=\nRestart=no\nWantedBy=\n"));
    // user show syncthing (detail)
    runner.queue(ok("FragmentPath=/home/u/.config/systemd/user/syncthing.service\nDropInPaths=\nRestart=on-failure\nWantedBy=default.target\n"));
    // system list-units fails (no privilege)
    runner.queue(CommandOutput::default());

    let inv = collect_services(&governor(), &runner);
    assert!(inv.user_available);
    assert!(!inv.system_available);
    let names: Vec<&str> = inv.services.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"syncthing.service"));
    assert!(!names.iter().any(|n| n.contains(';')), "hostile unit dropped");
    let sync = inv.services.iter().find(|s| s.name == "syncthing.service").unwrap();
    assert_eq!(sync.enabled, Some(true));
    assert_eq!(sync.active.as_deref(), Some("active/running"));
    assert_eq!(
        sync.unit_file.as_deref(),
        Some("/home/u/.config/systemd/user/syncthing.service")
    );
    assert_eq!(sync.restart.as_deref(), Some("on-failure"));
}

#[test]
fn environment_maps_names_never_secret_values() {
    let inv = collect_environment();
    assert!(inv.total > 0);
    // Histogram is consistent.
    let sum: usize = inv.by_class.values().sum();
    assert_eq!(sum, inv.total);
    // PATH (if present) is decomposed, never stored raw.
    if let Some(path_var) = inv.vars.iter().find(|v| v.name == "PATH") {
        let analysis = path_var.path_analysis.as_ref().expect("PATH analyzed");
        assert!(!analysis.entries.is_empty());
    }
    // Secret vars carry no value and no path analysis.
    for v in inv.vars.iter().filter(|v| v.classification == configctl_core::classify::EnvClass::Secret) {
        assert!(v.value.is_none(), "secret {} must not store a value", v.name);
        assert!(v.path_analysis.is_none());
    }
}

#[test]
fn credential_metadata_without_material() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("config"), "Host example\n  HostName example.com\n").unwrap();
    std::fs::write(ssh.join("known_hosts"), "example.com ssh-ed25519 AAAA\n# comment\n").unwrap();
    std::fs::write(ssh.join("id_ed25519"), "PRIVATE-MATERIAL-CANARY-12345\n").unwrap();
    std::fs::write(ssh.join("id_ed25519.pub"), "ssh-ed25519 AAAA user@host\n").unwrap();
    std::fs::create_dir_all(home.join(".gnupg")).unwrap();
    std::fs::write(home.join(".gnupg/gpg.conf"), "use-agent\n").unwrap();
    std::fs::create_dir_all(home.join(".aws")).unwrap();
    std::fs::write(home.join(".aws/credentials"), "[default]\naws_secret_access_key = CANARY\n").unwrap();

    let runner = FakeCommandRunner::new(); // git helper + ssh-keygen unavailable
    let inv = collect_credentials(&governor(), &runner, Some(home));
    // Private key: secret reference, material never captured anywhere.
    let privkey = inv
        .credentials
        .iter()
        .find(|c| c.path.ends_with("id_ed25519") && !c.path.ends_with(".pub"))
        .expect("private key recorded");
    assert_eq!(privkey.classification, configctl_core::classify::ResourceClass::Secret);
    assert_eq!(privkey.action, configctl_core::classify::CaptureAction::Reference);
    // Public key: type detected from public material, capturable.
    let pubkey = inv.credentials.iter().find(|c| c.path.ends_with(".pub")).expect("pub recorded");
    assert_eq!(pubkey.detail.as_deref(), Some("ssh-ed25519"));
    // known_hosts: entry count only.
    let kh = inv.credentials.iter().find(|c| c.path.ends_with("known_hosts")).unwrap();
    assert_eq!(kh.detail.as_deref(), Some("1 host entries"));
    // AWS credentials: existence only.
    assert!(inv.credentials.iter().any(|c| c.path.ends_with(".aws/credentials")));
    // No record anywhere contains private material.
    let json = serde_json::to_string(&inv).unwrap();
    assert!(!json.contains("PRIVATE-MATERIAL-CANARY-12345"));
    assert!(!json.contains("CANARY"));
}

#[test]
fn hardware_inventory_reports_host_context() {
    let runner = FakeCommandRunner::new();
    let inv = collect_hardware(&governor(), &runner, &[], vec!["gcc (12.3.0)".into()]);
    assert_eq!(inv.arch, std::env::consts::ARCH);
    assert!(!inv.boot_mode.is_empty());
    assert_eq!(inv.compilers, vec!["gcc (12.3.0)".to_string()]);
    // Must be JSON-serializable for scan reports.
    let json = serde_json::to_string(&inv).unwrap();
    assert!(json.contains("\"arch\""));
}

#[test]
fn env_files_mapped_inside_projects_with_roles() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("web");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("package.json"), "{}\n").unwrap();
    std::fs::write(proj.join(".env"), "A=1\n").unwrap();
    std::fs::write(proj.join(".env.production"), "B=2\n").unwrap();

    let runner = FakeCommandRunner::new();
    let mut scanner = Scanner::new();
    let opts = ScanOptions {
        roots: vec![tmp.path().to_path_buf()],
        limits: Default::default(),
        governor: Default::default(),
    };
    let result = scanner.scan(&opts, &runner);
    assert_eq!(result.env_files.len(), 2);
    let content = result.project_contents.iter().find(|c| c.project == "web").expect("roles");
    assert_eq!(content.roles.get("env_schema"), Some(&2));
    assert_eq!(content.roles.get("manifest"), Some(&1));
    let _ = Path::new(".");
}
