//! Verification / drift detection (P5). Strictly read-only: never repairs.
//!
//! Compares the profile's desired state with observed reality and emits one
//! [`CheckResult`] per resource with a status in
//! `MATCH | DRIFT | MISSING | UNMANAGED | UNKNOWN | UNSUPPORTED`.
//!
//! Secret-backed values verify existence/reference only — values are never
//! read, compared, or rendered.

use crate::observe::ObservedState;
use crate::profile::EnvLiteral;
use crate::profile_load::LoadedProfile;
use serde::{Deserialize, Serialize};

/// Per-resource verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Match,
    Drift,
    Missing,
    Unmanaged,
    Unknown,
    Unsupported,
}

/// One resource check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Resource class (`package`, `file`, `env`, `secret`, `service`, `git`).
    pub resource: String,
    /// Canonical target (name, `~/...` path, `VAR`, unit, `secret://...`).
    pub target: String,
    pub status: CheckStatus,
    /// Redaction-safe detail (never values).
    pub detail: String,
}

/// Full verification report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub schema_version: u32,
    pub profile: String,
    pub profile_hash: String,
    pub results: Vec<CheckResult>,
    pub summary: VerifySummary,
}

/// Counts per status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerifySummary {
    pub match_count: usize,
    pub drift: usize,
    pub missing: usize,
    pub unmanaged: usize,
    pub unknown: usize,
    pub unsupported: usize,
}

/// Verify a loaded profile against observed state. Pure and read-only.
pub fn verify(loaded: &LoadedProfile, observed: &ObservedState) -> VerifyReport {
    let mut results: Vec<CheckResult> = Vec::new();
    let profile = &loaded.profile;

    // Packages (apt, dnf, pacman share one honest shape: unavailable →
    // Unsupported, installed → Match/lock-drift, absent → Missing).
    verify_native_packages(
        &profile.packages.apt,
        &observed.packages,
        observed.packages_unavailable,
        loaded.lock.as_ref().map(|l| &l.apt),
        &mut results,
    );
    verify_native_packages(
        &profile.packages.dnf,
        &observed.dnf_packages,
        observed.dnf_unavailable,
        loaded.lock.as_ref().map(|l| &l.dnf),
        &mut results,
    );
    verify_native_packages(
        &profile.packages.pacman,
        &observed.pacman_packages,
        observed.pacman_unavailable,
        loaded.lock.as_ref().map(|l| &l.pacman),
        &mut results,
    );

    // Files (content identity vs payload hash).
    let mut files = profile.files.clone();
    files.sort_by(|a, b| a.target.cmp(&b.target));
    for f in &files {
        let desired = loaded.payload_hashes.get(&f.source);
        match observed.files.get(&f.target) {
            None => results.push(check(
                "file",
                &f.target,
                CheckStatus::Unknown,
                "not observed",
            )),
            Some(o) => {
                if o.is_symlink {
                    results.push(check(
                        "file",
                        &f.target,
                        CheckStatus::Unknown,
                        "symlink at target; refusing to resolve",
                    ));
                } else if o.is_non_regular {
                    results.push(check(
                        "file",
                        &f.target,
                        CheckStatus::Drift,
                        "non-regular file at target",
                    ));
                } else if !o.exists {
                    results.push(check(
                        "file",
                        &f.target,
                        CheckStatus::Missing,
                        "target absent",
                    ));
                } else if desired.is_some() && o.content_hash.as_ref() == desired {
                    results.push(check(
                        "file",
                        &f.target,
                        CheckStatus::Match,
                        "content matches",
                    ));
                } else if o.content_hash.is_none() || desired.is_none() {
                    results.push(check(
                        "file",
                        &f.target,
                        CheckStatus::Unknown,
                        "content unreadable",
                    ));
                } else {
                    results.push(check(
                        "file",
                        &f.target,
                        CheckStatus::Drift,
                        "content differs",
                    ));
                }
            }
        }
    }

    // Environment literals + secret refs.
    if let Some(env) = &profile.environment {
        let mut names: Vec<&String> = env.keys().collect();
        names.sort();
        for name in names {
            match &env[name.as_str()] {
                EnvLiteral::Value(lit) => match observed.env_literals.get(name) {
                    Some(cur) if cur == lit => {
                        results.push(check("env", name, CheckStatus::Match, "literal matches"));
                    }
                    Some(_) => {
                        results.push(check("env", name, CheckStatus::Drift, "literal differs"));
                    }
                    None => {
                        results.push(check(
                            "env",
                            name,
                            CheckStatus::Missing,
                            "not set in managed env file",
                        ));
                    }
                },
                EnvLiteral::Secret { secret, required } => match observed.secret_exists.get(secret)
                {
                    Some(Some(true)) => {
                        results.push(check(
                            "secret",
                            secret,
                            CheckStatus::Match,
                            "reference present",
                        ));
                    }
                    Some(Some(false)) => {
                        results.push(check(
                            "secret",
                            secret,
                            if *required {
                                CheckStatus::Missing
                            } else {
                                CheckStatus::Unmanaged
                            },
                            "reference missing in backend",
                        ));
                    }
                    _ => {
                        results.push(check(
                            "secret",
                            secret,
                            CheckStatus::Unknown,
                            "backend unavailable",
                        ));
                    }
                },
            }
        }

        // v1.2: when the canonical managed shell env file exists, the same
        // literals must be present there too — both artifacts are generated
        // from this one profile. Absence of the file is not drift; shell
        // consolidation is opt-in.
        if observed.envfile_present {
            let mut names: Vec<&String> = env.keys().collect();
            names.sort();
            for name in names {
                if let EnvLiteral::Value(lit) = &env[name.as_str()] {
                    match observed.envfile_literals.get(name) {
                        Some(cur) if cur == lit => results.push(check(
                            "envfile",
                            name,
                            CheckStatus::Match,
                            "managed shell env file matches",
                        )),
                        Some(_) => results.push(check(
                            "envfile",
                            name,
                            CheckStatus::Drift,
                            "managed shell env file differs",
                        )),
                        None => results.push(check(
                            "envfile",
                            name,
                            CheckStatus::Missing,
                            "not set in the managed shell env file",
                        )),
                    }
                }
            }
        }
    }
    if let Some(manifest) = &loaded.manifest {
        let mut refs: Vec<&crate::profile::SecretEntry> = manifest.secrets.iter().collect();
        refs.sort_by(|a, b| a.secret_ref.cmp(&b.secret_ref));
        for s in refs {
            match observed.secret_exists.get(&s.secret_ref) {
                Some(Some(true)) => {
                    results.push(check(
                        "secret",
                        &s.secret_ref,
                        CheckStatus::Match,
                        "reference present",
                    ));
                }
                Some(Some(false)) => {
                    results.push(check(
                        "secret",
                        &s.secret_ref,
                        if s.required {
                            CheckStatus::Missing
                        } else {
                            CheckStatus::Unmanaged
                        },
                        "reference missing in backend",
                    ));
                }
                _ => {
                    results.push(check(
                        "secret",
                        &s.secret_ref,
                        CheckStatus::Unknown,
                        "backend unavailable",
                    ));
                }
            }
        }
    }

    // Services.
    let mut services = profile.services.clone();
    services.sort_by(|a, b| a.name.cmp(&b.name));
    for s in &services {
        // v1.1: system-scope units verify as privileged context, never as
        // user-manager state.
        if s.scope.as_deref() == Some("system") {
            results.push(check(
                "service",
                &s.name,
                CheckStatus::Unsupported,
                "system scope (privileged; recorded only)",
            ));
            continue;
        }
        if observed.services_unavailable {
            results.push(check(
                "service",
                &s.name,
                CheckStatus::Unsupported,
                "user manager unavailable",
            ));
            continue;
        }
        match observed.services.get(&s.name) {
            None => results.push(check(
                "service",
                &s.name,
                CheckStatus::Unknown,
                "not observed",
            )),
            Some(o) if o.unknown => {
                results.push(check(
                    "service",
                    &s.name,
                    CheckStatus::Unknown,
                    "state unknown",
                ));
            }
            Some(o) => {
                let mut drift = false;
                let mut detail = String::new();
                if let Some(want) = s.enabled {
                    if o.enabled != Some(want) {
                        drift = true;
                        detail.push_str("enabled differs; ");
                    }
                }
                if let Some(want) = s.running {
                    if o.running != Some(want) {
                        drift = true;
                        detail.push_str("running differs; ");
                    }
                }
                if drift {
                    results.push(check("service", &s.name, CheckStatus::Drift, detail.trim()));
                } else {
                    results.push(check(
                        "service",
                        &s.name,
                        CheckStatus::Match,
                        "state matches",
                    ));
                }
            }
        }
    }

    // Git.
    if let Some(g) = &profile.git {
        if observed.git_unavailable {
            results.push(check(
                "git",
                "gitconfig",
                CheckStatus::Unknown,
                "git unavailable",
            ));
        } else {
            if let Some(want) = &g.user_name {
                if observed.git_user_name.as_deref() == Some(want.as_str()) {
                    results.push(check("git", "user.name", CheckStatus::Match, "matches"));
                } else {
                    results.push(check("git", "user.name", CheckStatus::Drift, "differs"));
                }
            }
            if let Some(want) = &g.user_email {
                if observed.git_user_email.as_deref() == Some(want.as_str()) {
                    results.push(check("git", "user.email", CheckStatus::Match, "matches"));
                } else {
                    results.push(check("git", "user.email", CheckStatus::Drift, "differs"));
                }
            }
        }
    }

    results.sort_by(|a, b| (&a.resource, &a.target).cmp(&(&b.resource, &b.target)));
    let mut summary = VerifySummary::default();
    for r in &results {
        match r.status {
            CheckStatus::Match => summary.match_count += 1,
            CheckStatus::Drift => summary.drift += 1,
            CheckStatus::Missing => summary.missing += 1,
            CheckStatus::Unmanaged => summary.unmanaged += 1,
            CheckStatus::Unknown => summary.unknown += 1,
            CheckStatus::Unsupported => summary.unsupported += 1,
        }
    }
    VerifyReport {
        schema_version: 1,
        profile: loaded.identity.clone(),
        profile_hash: loaded.profile_hash.clone(),
        results,
        summary,
    }
}

fn check(resource: &str, target: &str, status: CheckStatus, detail: &str) -> CheckResult {
    CheckResult {
        resource: resource.into(),
        target: target.into(),
        status,
        detail: detail.into(),
    }
}

/// One native package manager's slice of verification (shared by apt, dnf,
/// and pacman so every manager reports identically).
fn verify_native_packages(
    desired: &[String],
    installed: &std::collections::BTreeMap<String, String>,
    unavailable: bool,
    lock: Option<&std::collections::BTreeMap<String, String>>,
    results: &mut Vec<CheckResult>,
) {
    let mut names = desired.to_vec();
    names.sort();
    names.dedup();
    for name in &names {
        if unavailable {
            results.push(check(
                "package",
                name,
                CheckStatus::Unsupported,
                "package manager unavailable",
            ));
        } else if let Some(installed_version) = installed.get(name) {
            if let Some(lock_version) = lock.and_then(|l| l.get(name)) {
                if lock_version == installed_version {
                    results.push(check(
                        "package",
                        name,
                        CheckStatus::Match,
                        "installed version matches lock",
                    ));
                } else {
                    results.push(check(
                        "package",
                        name,
                        CheckStatus::Drift,
                        "installed version differs from lock (report-only; v1 never downgrades)",
                    ));
                }
            } else {
                results.push(check("package", name, CheckStatus::Match, "installed"));
            }
        } else {
            results.push(check(
                "package",
                name,
                CheckStatus::Missing,
                "not installed",
            ));
        }
    }
}

/// Overall outcome class for exit-code mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Everything matches (UNMANAGED/UNKNOWN/UNSUPPORTED tolerated).
    Clean,
    /// DRIFT or MISSING present.
    Drift,
    /// Only with `--strict`: UNMANAGED or UNKNOWN present (and no drift).
    StrictFindings,
}

pub fn outcome(report: &VerifyReport, strict: bool) -> VerifyOutcome {
    if report.summary.drift > 0 || report.summary.missing > 0 {
        VerifyOutcome::Drift
    } else if strict && (report.summary.unmanaged > 0 || report.summary.unknown > 0) {
        VerifyOutcome::StrictFindings
    } else {
        VerifyOutcome::Clean
    }
}
