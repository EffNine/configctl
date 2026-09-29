//! P2 capture pipeline: observed state → declarative profile.
//!
//! ```text
//! READ MACHINE (P1 ScanResult + package/git probes)
//! → SELECT MANAGED STATE (allowlist policies)
//! → REDACT SECRET MATERIAL (metadata only, never values)
//! → GENERATE PROFILE (typed model)
//! → VALIDATE PROFILE (fail-closed)
//! → WRITE PROFILE (atomic, inside output dir only)
//! ```
//!
//! Non-mutating w.r.t. the source environment: the only writes are inside the
//! explicit output directory.

use crate::command::CommandRunner;
use crate::env_schema::{self, ObservedVar, ObservedVarWithSource};
use crate::files;
use crate::gitmeta;
use crate::limits::Limits;
use crate::packages;
use crate::paths;
use crate::profile::{
    DirectoryEntry, EnvSchema, ExecutableEntry, FileEntry, GitConfig, HardwareSection,
    MachineSection, Metadata, MountEntry, PackagesLock, Platform, Profile, ProjectEntry,
    ProvenanceSection, SecretManifest, ToolchainEntry, SCHEMA_VERSION,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Home dotfiles eligible for payload capture (must also pass all safety
/// checks; secret-bearing files are excluded, never copied).
///
/// v1.1 broadens the candidate set aggressively (shell, editor, terminal,
/// toolchain configs) while keeping every safety gate: size caps, secret
/// screening, symlink rejection, and the classification policy in
/// [`crate::capture_policy`]. Candidates that fail any gate are listed in
/// the capture summary with an explicit reason — never silently dropped.
pub const HOME_ALLOWLIST: &[&str] = &[
    ".bash_profile",
    ".bashrc",
    ".curlrc",
    ".editorconfig",
    ".gitconfig",
    ".gitignore",
    ".gvimrc",
    ".ideavimrc",
    ".inputrc",
    ".node-version",
    ".nvmrc",
    ".profile",
    ".python-version",
    ".rust-toolchain",
    ".rust-toolchain.toml",
    ".tmux.conf",
    ".tool-versions",
    ".vimrc",
    ".wgetrc",
    ".zprofile",
    ".zshenv",
    ".zshrc",
];

/// Options for one capture run.
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    pub profile_name: String,
    pub description: Option<String>,
    pub scan_roots: Vec<PathBuf>,
    pub home: Option<PathBuf>,
    pub limits: Limits,
}

/// One file payload staged for bundle write.
#[derive(Debug, Clone)]
pub struct FilePayload {
    pub abs_source: PathBuf,
    pub bundle_rel: String,
    pub target: String,
    pub mode: String,
}

/// Deterministic capture summary (rendered human + JSON).
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(default)]
pub struct CaptureSummary {
    pub projects: usize,
    pub files: usize,
    pub packages: usize,
    pub installed_observed: usize,
    pub excluded_by_policy: usize,
    pub env_schemas: usize,
    pub secrets: usize,
    pub redacted: usize,
    pub excluded: Vec<String>,
    pub unsupported: Vec<String>,
    pub unknown: Vec<String>,
    pub warnings: Vec<String>,
    /// v1.1: explicit capture decisions (`capture → n`, …).
    pub capture_actions: BTreeMap<String, u64>,
    /// v1.1: counts for the new sections.
    pub toolchains: usize,
    pub services: usize,
    pub env_literals: usize,
    pub directories: usize,
}

/// The full capture result (in-memory; writing is a separate step).
#[derive(Debug, Clone)]
pub struct CaptureResult {
    pub profile: Profile,
    pub env_schemas: BTreeMap<String, EnvSchema>,
    pub manifest: SecretManifest,
    pub lock: PackagesLock,
    pub payloads: Vec<FilePayload>,
    pub summary: CaptureSummary,
    /// Secret values observed during scan (for post-write leak checks).
    /// Held only in memory; never serialized.
    pub secret_values: Vec<String>,
}

/// Run capture from a P1 [`ScanResult`] plus live package/git probes.
///
/// `scan` must have been produced from the same roots (the caller runs the
/// P1 scanner first). `registry_values` are the exact secret values
/// registered during scanning, used only for post-generation leak checks —
/// they are never written anywhere.
pub fn run_capture(
    opts: &CaptureOptions,
    scan: &scan_view::ScanView,
    runner: &dyn CommandRunner,
    registry_values: &[String],
) -> Result<CaptureResult, String> {
    // Validate profile name early (fail-closed).
    paths::validate_profile_name(&opts.profile_name)?;

    // --- Packages ---
    let pkg = packages::capture_packages(runner);
    let apt_names = packages::apt_names(&pkg);

    // --- Git ---
    let git: Option<GitConfig> = gitmeta::capture_git(runner);

    // --- Approved roots: scan roots + home ---
    let mut approved: Vec<PathBuf> = opts.scan_roots.clone();
    if let Some(h) = &opts.home {
        if !approved.iter().any(|r| r == h) {
            approved.push(h.clone());
        }
    }

    // --- Home file payloads ---
    let mut payloads: Vec<FilePayload> = Vec::new();
    let mut excluded: Vec<String> = Vec::new();
    let mut unsupported: Vec<String> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    let mut file_secret_excluded = 0usize;

    if let Some(home) = &opts.home {
        for name in HOME_ALLOWLIST {
            let abs = home.join(name);
            if !abs.exists() {
                continue;
            }
            match files::decide_file(&abs, &approved, opts.limits.max_file_bytes as u64) {
                files::FileDecision::Capture => {
                    // v1.1 classification gate (defense in depth): capture is
                    // aggressive by default, but secret/credential material
                    // and generated/cache content are vetoed even for
                    // allowlisted names. Everything else is captured with
                    // its classification recorded as provenance.
                    let class = crate::classify::classify_file(
                        &abs,
                        crate::classify::FileKind::Regular,
                        false,
                    );
                    match class.class {
                        crate::classify::ResourceClass::Secret
                        | crate::classify::ResourceClass::Credential
                        | crate::classify::ResourceClass::Generated
                        | crate::classify::ResourceClass::Cache => {
                            let policy = crate::capture_policy::decide_home_file(class.class);
                            excluded.push(format!("{}: {}", abs.display(), policy.reason));
                            continue;
                        }
                        _ => {}
                    }
                    // Bundle-relative payload path: `files/home/<stem>`.
                    let stem = name.trim_start_matches('.');
                    let rel = format!("files/home/{stem}");
                    let target = format!("~/{name}");
                    // Mode recorded at copy time; placeholder until copy.
                    let mode = source_mode(&abs);
                    payloads.push(FilePayload {
                        abs_source: abs.clone(),
                        bundle_rel: rel,
                        target,
                        mode,
                    });
                }
                files::FileDecision::Skip { reason } => {
                    if reason.starts_with("redacted_") {
                        file_secret_excluded += 1;
                    }
                    excluded.push(format!("{}: {reason}", abs.display()));
                }
            }
        }
    }

    // Project-local config files are metadata only (never copied): record
    // counts for the summary without touching payloads.
    let mut project_config_counts: BTreeMap<String, usize> = BTreeMap::new();
    for c in &scan.config_files {
        if let Some(proj) = &c.project {
            *project_config_counts.entry(proj.clone()).or_default() += 1;
        }
    }

    // --- Environment schemas + secret manifest inputs ---
    // Group observations by project. Values re-parsed from disk for type
    // inference only (never persisted); classifications come from the scan.
    let mut per_project_obs: BTreeMap<String, Vec<ObservedVarWithSource>> = BTreeMap::new();
    let mut per_project_schema_obs: BTreeMap<String, Vec<ObservedVar>> = BTreeMap::new();

    // Index scan classifications by (env path, var name).
    let mut class_index: BTreeMap<(String, String), String> = BTreeMap::new();
    for e in &scan.env_files {
        for v in &e.classifications {
            class_index.insert((e.path.clone(), v.name.clone()), v.classification.clone());
        }
    }

    for e in &scan.env_files {
        let project = e.project.clone().unwrap_or_else(|| "global".to_string());
        let filename = Path::new(&e.path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".env".into());
        let from_example = filename == ".env.example" || filename == ".env.sample";
        // Re-parse for values (bounded, in-memory only).
        let values_by_name = read_values_for_inference(Path::new(&e.path), &opts.limits);
        for var_name in &e.variable_names {
            let classification = class_index
                .get(&(e.path.clone(), var_name.clone()))
                .cloned()
                .unwrap_or_else(|| "unknown".into());
            let value = values_by_name.get(var_name).cloned();
            per_project_obs
                .entry(project.clone())
                .or_default()
                .push(ObservedVarWithSource {
                    name: var_name.clone(),
                    classification: classification.clone(),
                    source: filename.clone(),
                    from_example,
                });
            per_project_schema_obs
                .entry(project.clone())
                .or_default()
                .push(ObservedVar {
                    name: var_name.clone(),
                    classification,
                    from_example,
                    value,
                });
        }
    }
    // Deduplicate observations within a project+file (same var listed once
    // per file by the scanner already, but be deterministic anyway).
    for vars in per_project_obs.values_mut() {
        vars.sort_by(|a, b| (&a.name, &a.source).cmp(&(&b.name, &b.source)));
        vars.dedup_by(|a, b| a.name == b.name && a.source == b.source);
    }
    for vars in per_project_schema_obs.values_mut() {
        vars.sort_by(|a, b| a.name.cmp(&b.name));
        // Keep duplicates across files (they carry per-file value evidence);
        // dedupe exact duplicates only.
    }

    let mut env_schemas: BTreeMap<String, EnvSchema> = BTreeMap::new();
    for (project, obs) in &per_project_schema_obs {
        if obs.is_empty() {
            continue;
        }
        let schema = env_schema::build_env_schema(project, obs);
        env_schemas.insert(format!("env/{project}.toml"), schema);
    }

    let mut manifest = env_schema::build_secret_manifest(&opts.profile_name, &per_project_obs);
    // v1.1 global environment: secret refs enter the manifest (project None,
    // source `environment`); safe literals enter the profile below.
    let mut environment_literals: BTreeMap<String, crate::profile::EnvLiteral> = BTreeMap::new();
    {
        let mut seen_env: BTreeMap<String, bool> = BTreeMap::new();
        for g in scan.global_env.iter().take(512) {
            if g.name.is_empty() || seen_env.contains_key(&g.name) {
                continue;
            }
            seen_env.insert(g.name.clone(), true);
            if crate::paths::validate_env_name(&g.name).is_err() {
                excluded.push(format!("environment.{}: invalid variable name", g.name));
                continue;
            }
            let policy =
                crate::capture_policy::decide_global_env(match g.classification.as_str() {
                    "secret" => crate::classify::EnvClass::Secret,
                    "public_config" => crate::classify::EnvClass::PublicConfig,
                    "path" => crate::classify::EnvClass::Path,
                    "machine_specific" => crate::classify::EnvClass::MachineSpecific,
                    "runtime" => crate::classify::EnvClass::Runtime,
                    _ => crate::classify::EnvClass::Unknown,
                });
            match policy.action {
                crate::classify::CaptureAction::Reference => {
                    let secret_ref =
                        format!("secret://{}/{}/{}", opts.profile_name, "global", g.name);
                    if crate::paths::validate_secret_ref(&secret_ref).is_err() {
                        excluded.push(format!(
                            "environment.{}: unrepresentable secret ref",
                            g.name
                        ));
                        continue;
                    }
                    manifest.secrets.push(crate::profile::SecretEntry {
                        name: g.name.clone(),
                        project: None,
                        source: "environment".to_string(),
                        classification: "secret".to_string(),
                        backend: "secret-service".to_string(),
                        secret_ref: secret_ref.clone(),
                        required: false,
                    });
                    environment_literals.insert(
                        g.name.clone(),
                        crate::profile::EnvLiteral::Secret {
                            secret: secret_ref.clone(),
                            required: false,
                        },
                    );
                }
                crate::classify::CaptureAction::Capture => {
                    if let Some(v) = &g.value {
                        environment_literals
                            .insert(g.name.clone(), crate::profile::EnvLiteral::Value(v.clone()));
                    } else {
                        excluded.push(format!("environment.{}: {}", g.name, policy.reason));
                    }
                }
                _ => {
                    // Unknown stays unknown (mapped, never dropped); the rest
                    // is observed-with-reason in the excluded list.
                    if g.classification == "unknown" {
                        unknown.push(format!("environment.{}: {}", g.name, policy.reason));
                    } else {
                        excluded.push(format!("environment.{}: {}", g.name, policy.reason));
                    }
                }
            }
        }
        if scan.global_env.len() > 512 {
            excluded.push(format!(
                "environment: {} variable(s) beyond 512-cap not evaluated",
                scan.global_env.len() - 512
            ));
        }
        manifest
            .secrets
            .sort_by(|a, b| (&a.project, &a.name).cmp(&(&b.project, &b.name)));
    }
    let secrets_count = manifest.secrets.len();
    // Redacted = secret-like variables across all env files (metadata only).
    // File payloads excluded for secret content are reported in `excluded`;
    // the count here tracks secret *variables* whose values were never stored.
    let redacted_vars = per_project_obs
        .values()
        .flatten()
        .filter(|v| matches!(v.classification.as_str(), "secret" | "likely_secret"))
        .count();
    let _ = (file_secret_excluded, secrets_count);

    // --- Projects ---
    let home_str = opts.home.as_ref().map(|h| h.to_string_lossy().into_owned());
    let mut projects: Vec<ProjectEntry> = Vec::new();
    let mut project_warnings: Vec<String> = Vec::new();
    for p in &scan.projects {
        let portable = match &home_str {
            Some(h) => paths::to_portable(&p.path, h),
            None => p.path.clone(),
        };
        // A project located exactly at the home root maps to bare `~`,
        // which is not a representable project path. Record the omission
        // explicitly instead of failing the whole capture.
        if portable == "~" || portable == "~/" {
            project_warnings.push(format!(
                "project {:?} at home root not captured: bare `~` is not a representable project path",
                p.name
            ));
            continue;
        }
        let env_schema_ref = {
            let key = format!("env/{}.toml", p.name);
            if env_schemas.contains_key(&key) {
                Some(key)
            } else {
                None
            }
        };
        // Basenames of env/config files belonging to this project.
        let mut env_files: Vec<String> = scan
            .env_files
            .iter()
            .filter(|e| e.project.as_deref() == Some(p.name.as_str()))
            .map(|e| {
                Path::new(&e.path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        env_files.sort();
        env_files.dedup();
        let mut config_files: Vec<String> = scan
            .config_files
            .iter()
            .filter(|c| c.project.as_deref() == Some(p.name.as_str()))
            .map(|c| c.name.clone())
            .collect();
        config_files.sort();
        config_files.dedup();
        // Cap per-project file lists for determinism (bounded output).
        env_files.truncate(64);
        config_files.truncate(64);
        let mut ecosystems = p.hints.clone();
        ecosystems.sort();
        ecosystems.dedup();
        projects.push(ProjectEntry {
            name: p.name.clone(),
            path: portable,
            vcs: Some(p.vcs.clone()),
            ecosystems,
            env_schema: env_schema_ref,
            env_files,
            config_files,
            markers: scan
                .project_detail
                .get(&p.name)
                .map(|(m, _)| m.clone())
                .unwrap_or_default(),
            roles: scan
                .project_detail
                .get(&p.name)
                .map(|(_, r)| r.iter().cloned().collect())
                .unwrap_or_default(),
        });
    }
    projects.sort_by(|a, b| a.path.cmp(&b.path));

    // --- Files entries (from payloads) ---
    let mut file_entries: Vec<FileEntry> = payloads
        .iter()
        .map(|p| {
            // Record the discovery classification as provenance.
            let class = crate::classify::classify_file(
                &p.abs_source,
                crate::classify::FileKind::Regular,
                false,
            );
            FileEntry {
                target: p.target.clone(),
                source: p.bundle_rel.clone(),
                mode: Some(p.mode.clone()),
                origin: Some(if p.target.starts_with("~/") {
                    "home".to_string()
                } else {
                    "absolute".to_string()
                }),
                detected_by: Some("filesystem.discovery".to_string()),
                classification: Some(class.class.as_str().to_string()),
            }
        })
        .collect();
    file_entries.sort_by(|a, b| a.target.cmp(&b.target));

    // --- Platform ---
    let platform = Platform {
        os: "linux".into(),
        arch: std::env::consts::ARCH.to_string(),
        distro: scan.distro.clone(),
        kernel: scan.machine.as_ref().and_then(|m| m.kernel.clone()),
    };

    // --- v2 services (user units reproduced; system units privileged) ---
    let mut emitted_services: Vec<crate::profile::ServiceEntry> = Vec::new();
    {
        let mut user_count = 0usize;
        let mut system_count = 0usize;
        for s in &scan.services {
            if !s.name.ends_with(".service") {
                continue;
            }
            let user_scope = s.scope == "user";
            let (decision, _class) = crate::capture_policy::decide_service(user_scope);
            match decision.action {
                crate::classify::CaptureAction::Capture => {
                    if user_count >= 100 {
                        continue;
                    }
                    user_count += 1;
                    emitted_services.push(crate::profile::ServiceEntry {
                        name: s.name.clone(),
                        enabled: s.enabled,
                        running: None,
                        scope: Some("user".to_string()),
                        classification: Some("reproducible".to_string()),
                    });
                }
                _ => {
                    if system_count >= 50 {
                        continue;
                    }
                    system_count += 1;
                    emitted_services.push(crate::profile::ServiceEntry {
                        name: s.name.clone(),
                        enabled: s.enabled,
                        running: None,
                        scope: Some("system".to_string()),
                        classification: Some("privileged".to_string()),
                    });
                    // In-profile with explicit scope; plan gates execution
                    // as PRIVILEGED (apply never touches these unprivileged).
                }
            }
        }
    }

    // --- v2 sections (all informational; plan/apply semantics unchanged) ---
    let machine = scan.machine.as_ref().map(|m| MachineSection {
        hostname: None,
        kernel: m.kernel.clone(),
        boot_mode: m.boot_mode.clone().filter(|s| !s.is_empty()),
        root_filesystem: m.root_filesystem.clone(),
    });
    let hardware = scan.hardware.as_ref().map(|h| HardwareSection {
        cpu_model: h.cpu_model.clone(),
        logical_cpus: h.logical_cpus,
        total_ram_kib: h.total_ram_kib,
        gpus: h.gpus.clone(),
        cuda: h.cuda,
        rocm: h.rocm,
        compilers: h.compilers.clone(),
    });
    let mut packages_other: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (manager, name) in &scan.packages_other {
        packages_other
            .entry(manager.clone())
            .or_default()
            .push(name.clone());
    }
    let toolchains: Vec<ToolchainEntry> = {
        // Dedupe by name (first wins); adapters should already fold
        // multi-PATH duplicates, but the profile rejects them fail-closed.
        let mut seen = BTreeMap::new();
        for t in &scan.toolchains {
            seen.entry(t.name.clone())
                .or_insert_with(|| ToolchainEntry {
                    name: t.name.clone(),
                    version: t.version.clone(),
                    provenance: Some(t.provenance.clone()),
                });
        }
        seen.into_values().collect()
    };
    let directories: Vec<DirectoryEntry> = projects
        .iter()
        .map(|p| DirectoryEntry {
            path: p.path.clone(),
            kind: "project".to_string(),
            classification: None,
        })
        .collect();
    let mounts: Vec<MountEntry> = scan
        .mounts
        .iter()
        .map(|m| MountEntry {
            mountpoint: m.mountpoint.clone(),
            fstype: m.fstype.clone(),
            remote: m.remote,
            pseudo: m.pseudo,
        })
        .collect();
    let executables: Vec<ExecutableEntry> = {
        let mut seen = BTreeMap::new();
        for e in &scan.executables {
            seen.entry(e.name.clone())
                .or_insert_with(|| ExecutableEntry {
                    name: e.name.clone(),
                    provenance: e.provenance.clone(),
                    version: e.version.clone(),
                });
        }
        seen.into_values().collect()
    };

    // --- Lock file (record-and-report) ---
    let mut lock_apt: BTreeMap<String, String> = BTreeMap::new();
    for p in &pkg.selected {
        lock_apt.insert(p.name.clone(), p.version.clone());
    }
    // v1.1: lock versions for every other manager too (names only in the
    // profile; versions live here). Capped to bound bundle size.
    let mut lock_other: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    {
        let mut total = 0usize;
        for v in &scan.package_versions {
            if total >= 20000 {
                break;
            }
            if v.manager == "apt" || v.name.is_empty() || v.name.len() > 128 {
                continue;
            }
            if let Some(version) = &v.version {
                lock_other
                    .entry(v.manager.clone())
                    .or_default()
                    .insert(v.name.clone(), version.clone());
                total += 1;
            }
        }
    }

    let mut profile = Profile {
        schema_version: SCHEMA_VERSION,
        name: opts.profile_name.clone(),
        description: opts.description.clone(),
        configctl_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        metadata: Some(Metadata {
            captured_at: Some(rfc3339_now()),
            package_policy: Some(packages::POLICY_ID.into()),
        }),
        platform: Some(platform),
        machine,
        hardware,
        packages: crate::profile::Packages {
            apt: apt_names,
            other: packages_other,
        },
        toolchains,
        files: file_entries,
        directories,
        environment: if environment_literals.is_empty() {
            None
        } else {
            Some(environment_literals)
        },
        services: emitted_services,
        git,
        projects,
        mounts,
        executables,
        provenance: Some(ProvenanceSection {
            source: "scan".to_string(),
            migrated_from: None,
        }),
    };
    profile.canonicalize();

    // Package summary details.
    if pkg.unavailable {
        unsupported.push(
            "packages: package manager unavailable (dpkg-query failed); packages marked unknown"
                .into(),
        );
    } else if pkg.selected.is_empty() {
        excluded.push(format!(
            "packages: {} installed observed, 0 selected by {} (no recognized tooling installed)",
            pkg.installed_total,
            packages::POLICY_ID
        ));
    } else {
        excluded.push(format!(
            "packages: {} installed observed, {} selected by {}, {} excluded",
            pkg.installed_total,
            pkg.selected.len(),
            packages::POLICY_ID,
            pkg.excluded_by_policy
        ));
    }
    // Build-artifact / cache honesty: the P1 walker already excludes these;
    // surface the scanner's excluded-path count so capture never silently
    // pretends completeness.
    if scan.excluded_paths > 0 {
        excluded.push(format!(
            "walker: {} paths excluded by deny-list (build artifacts, caches, symlinks)",
            scan.excluded_paths
        ));
    }

    let mut summary_warnings = scan.warnings.clone();
    summary_warnings.extend(project_warnings);
    let summary = CaptureSummary {
        projects: profile.projects.len(),
        files: profile.files.len(),
        packages: profile.packages.apt.len(),
        installed_observed: pkg.installed_total,
        excluded_by_policy: pkg.excluded_by_policy,
        env_schemas: env_schemas.len(),
        secrets: secrets_count,
        redacted: redacted_vars,
        excluded,
        unsupported,
        unknown,
        warnings: summary_warnings,
        capture_actions: {
            // Explicit per-resource accounting across every captured
            // section: payloads, secret references, observed metadata.
            let mut decisions = Vec::new();
            for _ in &payloads {
                decisions.push(crate::capture_policy::CaptureDecision::capture(
                    "file payload",
                ));
            }
            for _ in 0..file_secret_excluded {
                decisions.push(crate::capture_policy::CaptureDecision::reference(
                    "secret file",
                ));
            }
            for _ in &profile.services {
                decisions.push(crate::capture_policy::CaptureDecision::observe("service"));
            }
            for _ in &profile.mounts {
                decisions.push(crate::capture_policy::CaptureDecision::observe("mount"));
            }
            for names in profile.packages.other.values() {
                for _ in names {
                    decisions.push(crate::capture_policy::CaptureDecision::capture(
                        "package name",
                    ));
                }
            }
            for _ in &profile.toolchains {
                decisions.push(crate::capture_policy::CaptureDecision::capture("toolchain"));
            }
            for _ in &profile.executables {
                decisions.push(crate::capture_policy::CaptureDecision::observe(
                    "executable",
                ));
            }
            if let Some(env) = &profile.environment {
                for lit in env.values() {
                    match lit {
                        crate::profile::EnvLiteral::Value(_) => decisions.push(
                            crate::capture_policy::CaptureDecision::capture("env literal"),
                        ),
                        crate::profile::EnvLiteral::Secret { .. } => decisions.push(
                            crate::capture_policy::CaptureDecision::reference("env secret"),
                        ),
                    }
                }
            }
            crate::capture_policy::summarize(&decisions)
        },
        toolchains: profile.toolchains.len(),
        services: profile.services.len(),
        env_literals: profile.environment.as_ref().map(|e| e.len()).unwrap_or(0),
        directories: profile.directories.len(),
    };

    // --- Validation (fail-closed: never report success on invalid) ---
    let mut errors = profile.validate();
    errors.extend(manifest.validate());
    for schema in env_schemas.values() {
        errors.extend(schema.validate().iter().map(|e| format!("env schema: {e}")));
    }
    if !errors.is_empty() {
        return Err(format!(
            "profile validation failed:\n  - {}",
            errors.join("\n  - ")
        ));
    }

    Ok(CaptureResult {
        profile,
        env_schemas,
        manifest,
        lock: PackagesLock {
            schema_version: SCHEMA_VERSION,
            apt: lock_apt,
            other: lock_other,
        },
        payloads,
        summary,
        secret_values: registry_values.to_vec(),
    })
}

/// Write a validated [`CaptureResult`] bundle into `out_dir`.
///
/// Layout:
///
/// ```text
/// <out_dir>/
/// ├── profile.toml
/// ├── secrets.manifest.toml
/// ├── packages.lock.toml
/// ├── env/<project>.toml
/// └── files/home/...
/// ```
///
/// Only `out_dir` is created/modified. Refuses a non-empty directory unless
/// `force` is set. All writes are atomic. After writing, every bundle file is
/// scanned for registered secret values; if any value is found, the write is
/// reported as failed (fail-closed).
pub fn write_bundle(
    result: &CaptureResult,
    out_dir: &Path,
    force: bool,
) -> Result<Vec<String>, String> {
    if out_dir.exists() {
        let non_empty = std::fs::read_dir(out_dir)
            .map(|mut it| it.next().is_some())
            .unwrap_or(false);
        if non_empty && !force {
            return Err(format!(
                "output directory {} is not empty (refusing to overwrite; use --force)",
                out_dir.display()
            ));
        }
    } else if let Some(parent) = out_dir.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create parent {}: {e:?}", parent.display()))?;
        }
    }
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("create output dir {}: {e:?}", out_dir.display()))?;
    let canon_out = std::fs::canonicalize(out_dir).unwrap_or_else(|_| out_dir.to_path_buf());

    let mut written: Vec<String> = Vec::new();

    // profile.toml
    let profile_toml = result.profile.to_toml()?;
    let profile_path = canon_out.join("profile.toml");
    files::atomic_write_inside(&canon_out, &profile_path, profile_toml.as_bytes())?;
    written.push("profile.toml".into());

    // secrets.manifest.toml
    let manifest_toml = result.manifest.to_toml()?;
    let manifest_path = canon_out.join("secrets.manifest.toml");
    files::atomic_write_inside(&canon_out, &manifest_path, manifest_toml.as_bytes())?;
    written.push("secrets.manifest.toml".into());

    // packages.lock.toml (only when packages were observed)
    if !result.lock.apt.is_empty() {
        let lock_toml = result.lock.to_toml()?;
        let lock_path = canon_out.join("packages.lock.toml");
        files::atomic_write_inside(&canon_out, &lock_path, lock_toml.as_bytes())?;
        written.push("packages.lock.toml".into());
    }

    // env schemas
    let mut env_keys: Vec<&String> = result.env_schemas.keys().collect();
    env_keys.sort();
    for key in env_keys {
        let schema = &result.env_schemas[key];
        let text = schema.to_toml()?;
        let dest = canon_out.join(key);
        files::atomic_write_inside(&canon_out, &dest, text.as_bytes())?;
        written.push(key.clone());
    }

    // file payloads (copy after validation; sources re-validated at copy time
    // in case the machine changed between decision and write).
    let mut payloads = result.payloads.clone();
    payloads.sort_by(|a, b| a.bundle_rel.cmp(&b.bundle_rel));
    for p in &payloads {
        crate::paths::validate_bundle_source(&p.bundle_rel)
            .map_err(|e| format!("payload {}: {e}", p.bundle_rel))?;
        let mode = files::copy_into_bundle(&p.abs_source, &canon_out, &p.bundle_rel)?;
        let _ = mode;
        written.push(p.bundle_rel.clone());
    }
    written.sort();
    written.dedup();

    // Post-write leak check: no registered secret value may appear in any
    // bundle file (fail-closed).
    leak_check(&canon_out, &result.secret_values)?;

    Ok(written)
}

/// Scan every bundle file for registered secret values. Fails closed on any
/// hit (the values themselves are never included in the error).
pub fn leak_check(bundle_dir: &Path, secret_values: &[String]) -> Result<(), String> {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(bundle_dir, &mut files);
    files.sort();
    for f in &files {
        let bytes = match std::fs::read(f) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // Skip absurdly large files (should not exist in a bundle).
        if bytes.len() > 4 * 1024 * 1024 {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        for v in secret_values {
            if v.len() < 4 {
                continue;
            }
            if text.contains(v) {
                let rel = f
                    .strip_prefix(bundle_dir)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| f.display().to_string());
                return Err(format!(
                    "secret leak detected in bundle file {rel}: capture aborted (value redacted from this error)"
                ));
            }
        }
    }
    Ok(())
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for e in entries.filter_map(|c| c.ok()) {
        let p = e.path();
        if let Ok(m) = std::fs::symlink_metadata(&p) {
            if m.file_type().is_dir() {
                collect_files(&p, out);
            } else if m.file_type().is_file() {
                out.push(p);
            }
        }
    }
}

/// Read an env file's values for in-memory type inference only.
///
/// Never logs or persists values. Malformed/oversized files yield empty maps
/// (schema falls back to safe defaults).
fn read_values_for_inference(path: &Path, limits: &Limits) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let parsed = match crate::envfile::parse_file(
        path,
        &crate::envfile::ParseLimits {
            max_bytes: limits.max_file_bytes,
            max_variables: limits.max_findings,
        },
    ) {
        Ok(p) => p,
        Err(_) => return map,
    };
    for v in &parsed.variables {
        // First occurrence wins (deterministic: file order).
        v.with_value(|val| {
            map.entry(v.name.clone()).or_insert_with(|| val.to_string());
        });
    }
    map
}

fn source_mode(abs: &Path) -> String {
    match std::fs::symlink_metadata(abs) {
        Ok(m) => files::mode_string(&m),
        Err(_) => "0644".into(),
    }
}

fn rfc3339_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = (secs / 86400) as i64;
    let secs_of_day = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 152;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// A minimal, redaction-safe view over the P1 `ScanResult`.
///
/// Defined here (rather than depending on `configctl-discovery`, which would
/// invert the provider→core dependency direction) so `configctl-core` stays
/// platform-independent. The CLI crate adapts the real `ScanResult` into
/// this view.
#[derive(Debug, Clone, Default)]
pub struct ScanViewAdapter {
    _private: (),
}

pub mod scan_view {
    //! Adapter types mirroring the redaction-safe fields of the P1 scan.

    /// project name → (markers, role counts).
    pub type ProjectDetailMap =
        std::collections::BTreeMap<String, (Vec<String>, Vec<(String, u64)>)>;

    #[derive(Debug, Clone, Default)]
    pub struct ScanView {
        pub projects: Vec<ProjectView>,
        pub env_files: Vec<EnvFileView>,
        pub config_files: Vec<ConfigFileView>,
        pub distro: Option<String>,
        pub excluded_paths: usize,
        pub warnings: Vec<String>,
        /// v1.1 machine context (populated by the CLI adapter; `None`
        /// preserves v1 behavior).
        pub machine: Option<MachineView>,
        pub hardware: Option<HardwareView>,
        /// (manager, name) pairs beyond apt.
        pub packages_other: Vec<(String, String)>,
        pub toolchains: Vec<ToolchainView>,
        pub mounts: Vec<MountView>,
        pub executables: Vec<ExecutableView>,
        /// project name → (markers, role counts).
        pub project_detail: ProjectDetailMap,
        /// v1.1 systemd units to consider for emission.
        pub services: Vec<ServiceView>,
        /// v1.1 global environment to consider for emission.
        pub global_env: Vec<GlobalEnvView>,
        /// v1.1 (manager, name, version) for the packages lock.
        pub package_versions: Vec<PackageVersionView>,
    }

    #[derive(Debug, Clone, Default)]
    pub struct MachineView {
        pub hostname: Option<String>,
        pub kernel: Option<String>,
        pub boot_mode: Option<String>,
        pub root_filesystem: Option<String>,
    }

    #[derive(Debug, Clone, Default)]
    pub struct HardwareView {
        pub cpu_model: Option<String>,
        pub logical_cpus: Option<u32>,
        pub total_ram_kib: Option<u64>,
        pub gpus: Vec<String>,
        pub cuda: Option<bool>,
        pub rocm: Option<bool>,
        pub compilers: Vec<String>,
    }

    #[derive(Debug, Clone)]
    pub struct ToolchainView {
        pub name: String,
        pub version: Option<String>,
        pub provenance: String,
    }

    #[derive(Debug, Clone)]
    pub struct MountView {
        pub mountpoint: String,
        pub fstype: String,
        pub remote: bool,
        pub pseudo: bool,
    }

    #[derive(Debug, Clone)]
    pub struct ExecutableView {
        pub name: String,
        pub version: Option<String>,
        pub provenance: String,
    }

    #[derive(Debug, Clone)]
    pub struct ServiceView {
        pub name: String,
        pub scope: String,
        pub enabled: Option<bool>,
        pub active: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct GlobalEnvView {
        pub name: String,
        /// `secret` | `public_config` | `path` | `machine_specific` |
        /// `runtime` | `unknown`.
        pub classification: String,
        /// Truncated value, only for display-safe names.
        pub value: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct PackageVersionView {
        pub manager: String,
        pub name: String,
        pub version: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct ProjectView {
        pub path: String,
        pub name: String,
        pub vcs: String,
        pub hints: Vec<String>,
    }

    #[derive(Debug, Clone)]
    pub struct EnvFileView {
        pub path: String,
        pub project: Option<String>,
        pub variable_names: Vec<String>,
        pub classifications: Vec<VarClass>,
    }

    #[derive(Debug, Clone)]
    pub struct VarClass {
        pub name: String,
        pub classification: String,
    }

    #[derive(Debug, Clone)]
    pub struct ConfigFileView {
        pub path: String,
        pub name: String,
        pub project: Option<String>,
    }
}
