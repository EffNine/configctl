//! v1.1 SSH / GPG / credential metadata discovery.
//!
//! Records that credential systems *exist* — types, permissions, associated
//! configuration — without ever capturing private key material, tokens, or
//! cloud credentials. Content reads are limited to public or structural
//! files (`.pub` keys, config skeletons); secret-bearing files contribute
//! existence + mode only.

use configctl_core::classify::{CaptureAction, ResourceClass};
use configctl_core::command::CommandRunner;
use configctl_core::governor::{ResourceGovernor, governed_run};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Credential record kind.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    SshConfig,
    SshKnownHosts,
    SshPublicKey,
    SshPrivateKey,
    GpgConfig,
    GitCredentialHelper,
    GhHosts,
    AwsConfig,
    AwsCredentials,
    GcloudConfig,
    AzureConfig,
}

/// One credential metadata observation (never material).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CredentialRecord {
    pub path: String,
    pub kind: CredentialKind,
    pub exists: bool,
    /// Octal mode string when the file exists (e.g. `"0600"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Key type (`ssh-ed25519`, …) for public keys; helper name for git.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Fingerprint when safely available (public keys via ssh-keygen).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub classification: ResourceClass,
    pub action: CaptureAction,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CredentialInventory {
    pub credentials: Vec<CredentialRecord>,
    pub warnings: Vec<String>,
}

fn octal_mode(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path)
            .ok()
            .map(|m| format!("{:04o}", m.mode() & 0o7777))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn secret_ref(path: &str, why: &str) -> CredentialRecord {
    CredentialRecord {
        path: path.to_string(),
        kind: CredentialKind::SshPrivateKey,
        exists: true,
        mode: None,
        detail: None,
        fingerprint: None,
        classification: ResourceClass::Secret,
        action: CaptureAction::Reference,
        reason: why.to_string(),
    }
}

/// Fingerprint a PUBLIC key via fixed-argv `ssh-keygen -lf` (governed).
/// Private keys are never passed to any subprocess.
fn fingerprint_public_key(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
    pub_path: &Path,
) -> Option<String> {
    let out = governed_run(governor, runner, "ssh-keygen", ["-lf", &pub_path.to_string_lossy()].iter())
        .ok()?;
    if out.status != Some(0) {
        return None;
    }
    // `256 SHA256:... comment (TYPE)` — keep the hash token only.
    let token = out.stdout.split_whitespace().nth(1)?.to_string();
    if token.starts_with("SHA256:") && token.len() < 128 {
        Some(token)
    } else {
        None
    }
}

/// Read the key type token from a public key file (public material; the
/// file is world-readable by design). Bounded to 4KiB.
fn public_key_type(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    let first = text.lines().next()?.trim();
    let token = first.split_whitespace().next()?;
    if matches!(
        token,
        "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "sk-ssh-ed25519@openssh.com" | "sk-ecdsa-sha2-nistp256@openssh.com"
    ) {
        Some(token.to_string())
    } else {
        None
    }
}

const PRIVATE_KEY_NAMES: &[&str] = &[
    "id_ed25519",
    "id_rsa",
    "id_ecdsa",
    "id_dsa",
    "id_ed25519_sk",
    "id_ecdsa_sk",
    "identity",
];

/// Collect credential metadata under `home`. Never reads private material.
pub fn collect_credentials(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
    home: Option<&Path>,
) -> CredentialInventory {
    let mut inv = CredentialInventory::default();
    let Some(home) = home else {
        inv.warnings.push("no home directory; credential discovery skipped".into());
        return inv;
    };

    let ssh = home.join(".ssh");
    // ~/.ssh/config — metadata (hosts, not secrets); existence + mode.
    let ssh_config = ssh.join("config");
    if ssh_config.is_file() {
        let mode = octal_mode(&ssh_config);
        let mut rec = CredentialRecord {
            path: ssh_config.to_string_lossy().into_owned(),
            kind: CredentialKind::SshConfig,
            exists: true,
            mode: mode.clone(),
            detail: None,
            fingerprint: None,
            classification: ResourceClass::Credential,
            action: CaptureAction::Observe,
            reason: "SSH client configuration metadata observed; hostnames may be machine-specific"
                .into(),
        };
        // Overly broad permissions on ssh/config weaken the whole setup.
        if let Some(m) = &mode {
            if m != "0600" && m != "0644" && m != "0400" {
                inv.warnings.push(format!("{} has unusual permissions ({m})", rec.path));
            }
        }
        inv.credentials.push(rec);
    }
    // known_hosts — count entries (bounded read), never content.
    let known_hosts = ssh.join("known_hosts");
    if known_hosts.is_file() {
        let count = std::fs::read(&known_hosts)
            .ok()
            .filter(|b| b.len() <= 1024 * 1024)
            .map(|b| {
                String::from_utf8_lossy(&b)
                    .lines()
                    .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                    .count()
            });
        inv.credentials.push(CredentialRecord {
            path: known_hosts.to_string_lossy().into_owned(),
            kind: CredentialKind::SshKnownHosts,
            exists: true,
            mode: octal_mode(&known_hosts),
            detail: count.map(|c| format!("{c} host entries")),
            fingerprint: None,
            classification: ResourceClass::Credential,
            action: CaptureAction::Observe,
            reason: "known-hosts entry count observed; host keys not captured".into(),
        });
    }
    // Keys: public companions recorded with type+fingerprint; private keys
    // recorded as secret references (existence + mode only).
    if ssh.is_dir() {
        let entries = std::fs::read_dir(&ssh)
            .map(|it| it.filter_map(|e| e.ok()).take(64).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut names: Vec<String> = entries
            .iter()
            .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
            .collect();
        names.sort();
        let mut fingerprinted = 0usize;
        for name in names {
            let path = ssh.join(&name);
            if name.ends_with(".pub") {
                let key_type = public_key_type(&path);
                let fingerprint = if fingerprinted < 5 {
                    fingerprinted += 1;
                    fingerprint_public_key(governor, runner, &path)
                } else {
                    None
                };
                inv.credentials.push(CredentialRecord {
                    path: path.to_string_lossy().into_owned(),
                    kind: CredentialKind::SshPublicKey,
                    exists: true,
                    mode: octal_mode(&path),
                    detail: key_type,
                    fingerprint,
                    classification: ResourceClass::Credential,
                    action: CaptureAction::Capture,
                    reason: "public key material is safe to capture".into(),
                });
            } else if PRIVATE_KEY_NAMES.contains(&name.as_str()) {
                let mut rec = secret_ref(
                    &path.to_string_lossy(),
                    "private key material never captured; existence recorded",
                );
                rec.mode = octal_mode(&path);
                if rec.mode.as_deref() != Some("0600") && rec.mode.as_deref() != Some("0400") {
                    inv.warnings.push(format!(
                        "private key {} has broad permissions ({})",
                        rec.path,
                        rec.mode.as_deref().unwrap_or("?")
                    ));
                }
                inv.credentials.push(rec);
            }
        }
    }

    // GPG configuration skeletons (never keyrings).
    let gnupg = home.join(".gnupg");
    for conf in ["gpg.conf", "gpg-agent.conf", "dirmngr.conf", "sshcontrol"] {
        let p = gnupg.join(conf);
        if p.is_file() {
            inv.credentials.push(CredentialRecord {
                path: p.to_string_lossy().into_owned(),
                kind: CredentialKind::GpgConfig,
                exists: true,
                mode: octal_mode(&p),
                detail: Some(conf.to_string()),
                fingerprint: None,
                classification: ResourceClass::Credential,
                action: CaptureAction::Observe,
                reason: "GPG configuration observed; key material never touched".into(),
            });
        }
    }

    // Git credential helper: helper NAME only (never contents).
    if let Ok(out) = governed_run(governor, runner, "git", ["config", "--global", "credential.helper"].iter()) {
        if out.status == Some(0) {
            if let Some(helper) = out.stdout.lines().next().and_then(|l| {
                let c: String = l.trim().chars().filter(|c| !c.is_control()).take(128).collect();
                if c.is_empty() { None } else { Some(c) }
            }) {
                inv.credentials.push(CredentialRecord {
                    path: "git:credential.helper".into(),
                    kind: CredentialKind::GitCredentialHelper,
                    exists: true,
                    mode: None,
                    detail: Some(helper),
                    fingerprint: None,
                    classification: ResourceClass::Credential,
                    action: CaptureAction::Observe,
                    reason: "credential helper name observed; stored secrets stay in the helper"
                        .into(),
                });
            }
        }
    }

    // Secret-bearing existence-only records (content never read).
    let secret_paths: &[(&str, CredentialKind, &str)] = &[
        (".config/gh/hosts.yml", CredentialKind::GhHosts, "GitHub CLI hosts file exists; tokens never read"),
        (".aws/credentials", CredentialKind::AwsCredentials, "AWS credentials file exists; keys never read"),
        (".aws/config", CredentialKind::AwsConfig, "AWS config exists; metadata only"),
        (".config/gcloud", CredentialKind::GcloudConfig, "gcloud config dir exists; tokens never read"),
        (".azure", CredentialKind::AzureConfig, "azure config dir exists; tokens never read"),
    ];
    for (rel, kind, reason) in secret_paths {
        let p: PathBuf = home.join(rel);
        let exists = if matches!(kind, CredentialKind::GcloudConfig | CredentialKind::AzureConfig) {
            p.is_dir()
        } else {
            p.is_file()
        };
        if exists {
            inv.credentials.push(CredentialRecord {
                path: p.to_string_lossy().into_owned(),
                kind: kind.clone(),
                exists: true,
                mode: octal_mode(&p),
                detail: None,
                fingerprint: None,
                classification: ResourceClass::Secret,
                action: CaptureAction::Reference,
                reason: (*reason).into(),
            });
        }
    }

    inv.credentials.sort_by(|a, b| a.path.cmp(&b.path));
    inv
}
