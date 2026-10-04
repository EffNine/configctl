//! `configctl capture` — observed state → declarative profile.
//!
//! Non-mutating w.r.t. the source environment: the only writes are inside the
//! explicit output directory. `--dry-run` writes nothing.

use crate::commands::scan::{default_roots, expand_root};
pub use crate::commands::scan::{governor_from_flags, ScanGovernorFlags};
use configctl_core::capture::{self, CaptureOptions};
use configctl_core::command::CommandRunner;
use configctl_core::limits::Limits;
use configctl_discovery::scanner::{ScanOptions, Scanner};
use std::path::{Path, PathBuf};

/// Result of running the capture command.
pub struct CaptureOutput {
    /// In-memory capture result (profile + schemas + summary).
    pub result: Option<capture::CaptureResult>,
    /// Files that were (or would be, under `--dry-run`) written, relative to
    /// the output dir, sorted.
    pub written: Vec<String>,
    /// Output directory used.
    pub out_dir: PathBuf,
    /// Whether this was a dry run (no writes).
    pub dry_run: bool,
    /// Usage/validation error envelope, if any.
    pub error_envelope: Option<crate::render::Envelope>,
    /// CLI exit code (see CLI_SPEC §1.1): 0 on success, 2 on usage/other
    /// errors, 5 when a non-empty output directory is refused without
    /// `--force` (conflict-class, matching `onboard` and the CLI spec).
    pub exit_code: i32,
    /// The redaction registry populated during scan; callers redact every
    /// sink before output.
    pub registry: std::sync::Arc<configctl_core::redact::SecretRegistry>,
}

/// True when the directory exists and already holds anything.
fn non_empty_dir(p: &Path) -> bool {
    std::fs::read_dir(p)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false)
}

/// Resolve the profile name: explicit `name` arg wins; otherwise the output
/// directory basename; otherwise `captured`.
fn resolve_name(explicit: Option<&str>, out_dir: &Path) -> String {
    if let Some(n) = explicit {
        if !n.is_empty() {
            return n.to_string();
        }
    }
    if let Some(base) = out_dir.file_name().and_then(|n| n.to_str()) {
        if !base.is_empty() && base != "." && base != "/" {
            // Sanitize to the profile-name grammar: lowercase, `-`/`_`.
            let mut s: String = base
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .collect();
            s = s.trim_matches('-').to_string();
            if !s.is_empty() && s.len() <= 64 {
                // Must start with alnum.
                if s.chars()
                    .next()
                    .map(|c| c.is_ascii_alphanumeric())
                    .unwrap_or(false)
                {
                    return s;
                }
            }
        }
    }
    "captured".into()
}

/// Run capture.
///
/// - `name`: optional positional profile name (P0 form `capture <NAME>`).
/// - `from_roots` / `extra_roots`: scan roots (`--from` / `--root`, plus
///   positional scan paths for `scan` parity — capture accepts the same root
///   flags as scan).
/// - `output`: explicit destination (`--output` / `--out`); defaults to
///   `./configctl-profile`.
/// - `force`: overwrite a non-empty output directory.
/// - `depth`: optional walker depth bound.
/// - `dry_run`: analyze without writing.
/// - `description`: optional profile description.
#[allow(clippy::too_many_arguments)]
pub fn run_capture(
    name: Option<&str>,
    from_roots: &[String],
    extra_roots: &[String],
    output: Option<&str>,
    force: bool,
    depth: Option<usize>,
    dry_run: bool,
    description: Option<&str>,
    runner: &dyn CommandRunner,
) -> CaptureOutput {
    run_capture_with_governor(
        name,
        from_roots,
        extra_roots,
        output,
        force,
        depth,
        dry_run,
        description,
        configctl_core::governor::GovernorBudgets::default(),
        runner,
    )
}

/// Governor-aware capture entry point (v1.1).
#[allow(clippy::too_many_arguments)]
pub fn run_capture_with_governor(
    name: Option<&str>,
    from_roots: &[String],
    extra_roots: &[String],
    output: Option<&str>,
    force: bool,
    depth: Option<usize>,
    dry_run: bool,
    description: Option<&str>,
    governor: configctl_core::governor::GovernorBudgets,
    runner: &dyn CommandRunner,
) -> CaptureOutput {
    let home = dirs::home_dir();
    let out_dir: PathBuf = match output {
        Some(o) => {
            if let Some(h) = home.as_deref() {
                super::scan::expand_root(o, h)
            } else {
                PathBuf::from(o)
            }
        }
        None => std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("configctl-profile"),
    };
    let profile_name = resolve_name(name, &out_dir);
    // Fail fast on an overwrite refusal (exit 5, conflict-class per CLI_SPEC
    // §2.3) before the expensive discovery scan: nothing is read, nothing is
    // written. `--dry-run` previews without writing, so it is exempt; the
    // write-time refusal below stays as the fail-closed backstop (exit 2) for
    // the residual race where the directory fills between this check and the
    // write.
    if !dry_run && !force && non_empty_dir(&out_dir) {
        return CaptureOutput {
            result: None,
            written: Vec::new(),
            out_dir,
            dry_run,
            error_envelope: Some(crate::render::Envelope::error(
                "capture",
                "output directory is not empty (refusing to overwrite; use --force)",
                "re-run with --force to overwrite, or choose an empty --output directory",
            )),
            exit_code: 5,
            registry: std::sync::Arc::new(configctl_core::redact::SecretRegistry::default()),
        };
    }
    if let Err(e) = configctl_core::paths::validate_profile_name(&profile_name) {
        return CaptureOutput {
            result: None,
            written: Vec::new(),
            out_dir,
            dry_run,
            error_envelope: Some(crate::render::Envelope::error(
                "capture",
                &e,
                "use --output <DIR> and an optional NAME matching [a-z0-9][a-z0-9-_]{0,63}",
            )),
            exit_code: 2,
            registry: std::sync::Arc::new(configctl_core::redact::SecretRegistry::default()),
        };
    }

    // Collect scan roots: --from + --root + defaults (same as scan).
    let mut roots: Vec<PathBuf> = Vec::new();
    let h = home.as_deref();
    for r in from_roots.iter().chain(extra_roots.iter()) {
        if let Some(h) = h {
            roots.push(expand_root(r, h));
        } else {
            roots.push(PathBuf::from(r));
        }
    }
    if roots.is_empty() {
        let defaults = default_roots(h);
        // Keep only existing defaults; if none exist, fall back to the
        // current directory so `capture` works in fixtures without HOME
        // project dirs.
        let existing: Vec<PathBuf> = defaults.into_iter().filter(|p| p.exists()).collect();
        if existing.is_empty() {
            if let Ok(cwd) = std::env::current_dir() {
                roots.push(cwd);
            }
        } else {
            roots.extend(existing);
        }
    }
    {
        let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
        roots.retain(|p| seen.insert(p.clone()));
    }
    if roots.is_empty() {
        return CaptureOutput {
            result: None,
            written: Vec::new(),
            out_dir,
            dry_run,
            error_envelope: Some(crate::render::Envelope::error(
                "capture",
                "no scan roots available",
                "pass --from <PATH> to select what to capture",
            )),
            exit_code: 2,
            registry: std::sync::Arc::new(configctl_core::redact::SecretRegistry::default()),
        };
    }

    let mut limits = Limits::default();
    if let Some(d) = depth {
        limits = Limits {
            max_depth: d,
            ..limits
        };
    }

    // 1. P1 discovery (read-only).
    let mut scanner = Scanner::new();
    let scan_opts = ScanOptions {
        roots: roots.clone(),
        limits: limits.clone(),
        governor,
    };
    let scan_result = scanner.scan(&scan_opts, runner);
    let registry = scanner.registry().clone();
    let secret_values = registry.snapshot_values();

    // 2. Adapt ScanResult → core ScanView (keeps core independent of discovery).
    let view = adapt_scan(&scan_result);

    // 3. Capture pipeline.
    let cap_opts = CaptureOptions {
        profile_name: profile_name.clone(),
        description: description.map(|s| s.to_string()),
        scan_roots: roots,
        home: home.clone(),
        limits,
    };
    let cap_result = match capture::run_capture(&cap_opts, &view, runner, &secret_values) {
        Ok(r) => r,
        Err(e) => {
            let e = registry.redact(&e);
            return CaptureOutput {
                result: None,
                written: Vec::new(),
                out_dir,
                dry_run,
                error_envelope: Some(crate::render::Envelope::error(
                    "capture",
                    &e,
                    "fix the reported issue and re-run capture",
                )),
                exit_code: 2,
                registry,
            };
        }
    };

    // 4. Write (unless dry-run).
    if dry_run {
        // Validate serialization round-trip even in dry-run (no writes).
        let written = preview_written(&cap_result);
        return CaptureOutput {
            result: Some(cap_result),
            written,
            out_dir,
            dry_run: true,
            error_envelope: None,
            exit_code: 0,
            registry,
        };
    }
    match capture::write_bundle(&cap_result, &out_dir, force) {
        Ok(written) => CaptureOutput {
            result: Some(cap_result),
            written,
            out_dir,
            dry_run: false,
            error_envelope: None,
            exit_code: 0,
            registry,
        },
        Err(e) => {
            let e = registry.redact(&e);
            CaptureOutput {
                result: Some(cap_result),
                written: Vec::new(),
                out_dir,
                dry_run: false,
                error_envelope: Some(crate::render::Envelope::error(
                    "capture",
                    &e,
                    "re-run with --force to overwrite, or choose an empty --output directory",
                )),
                exit_code: 2,
                registry,
            }
        }
    }
}

fn preview_written(result: &capture::CaptureResult) -> Vec<String> {
    let mut v = vec![
        "profile.toml".to_string(),
        "secrets.manifest.toml".to_string(),
    ];
    if !result.lock.apt.is_empty() {
        v.push("packages.lock.toml".to_string());
    }
    for k in result.env_schemas.keys() {
        v.push(k.clone());
    }
    for p in &result.payloads {
        v.push(p.bundle_rel.clone());
    }
    v.sort();
    v.dedup();
    v
}

fn adapt_scan(r: &configctl_discovery::ScanResult) -> capture::scan_view::ScanView {
    use capture::scan_view as stub;
    stub::ScanView {
        projects: r
            .projects
            .iter()
            .map(|p| stub::ProjectView {
                path: p.path.clone(),
                name: p.name.clone(),
                vcs: p.vcs.clone(),
                hints: p.hints.clone(),
            })
            .collect(),
        env_files: r
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
        config_files: r
            .config_files
            .iter()
            .map(|c| stub::ConfigFileView {
                path: c.path.clone(),
                name: c.name.clone(),
                project: c.project.clone(),
            })
            .collect(),
        distro: r.system.distro.clone(),
        excluded_paths: r.statistics.excluded_paths,
        warnings: r.warnings.clone(),
        machine: Some(stub::MachineView {
            hostname: r.system.hostname.clone(),
            kernel: r.system.kernel.clone(),
            boot_mode: Some(r.hardware.boot_mode.clone()),
            root_filesystem: r.hardware.root_filesystem.clone(),
        }),
        hardware: Some(stub::HardwareView {
            cpu_model: r.hardware.cpu.model.clone(),
            logical_cpus: Some(r.hardware.cpu.logical_count as u32),
            total_ram_kib: Some(r.hardware.memory.total_kib),
            gpus: r
                .hardware
                .gpus
                .iter()
                .map(|g| g.description.clone())
                .collect(),
            cuda: Some(r.hardware.accelerators.cuda),
            rocm: Some(r.hardware.accelerators.rocm),
            compilers: r.hardware.compilers.clone(),
        }),
        packages_other: {
            let mut v = Vec::new();
            for p in &r.package_inventory.packages {
                if p.manager != "apt" {
                    v.push((p.manager.clone(), p.name.clone()));
                }
            }
            v.sort();
            v.dedup();
            v
        },
        toolchains: {
            // One entry per tool name (first PATH hit wins — standard PATH
            // semantics); duplicates across bin dirs are folded, never stored.
            let mut seen = std::collections::BTreeSet::new();
            r.toolchain
                .executables
                .iter()
                .filter(|e| e.version.is_some())
                .filter(|e| seen.insert(e.name.clone()))
                .take(128)
                .map(|e| stub::ToolchainView {
                    name: e.name.clone(),
                    version: e.version.clone(),
                    provenance: e.provenance.clone(),
                })
                .collect()
        },
        mounts: r
            .mounts
            .iter()
            .filter(|m| !m.pseudo)
            .take(256)
            .map(|m| stub::MountView {
                mountpoint: m.mountpoint.clone(),
                fstype: m.fstype.clone(),
                remote: m.remote,
                pseudo: m.pseudo,
            })
            .collect(),
        executables: {
            let mut seen = std::collections::BTreeSet::new();
            r.toolchain
                .executables
                .iter()
                .filter(|e| e.version.is_some())
                .filter(|e| seen.insert(e.name.clone()))
                .take(128)
                .map(|e| stub::ExecutableView {
                    name: e.name.clone(),
                    version: e.version.clone(),
                    provenance: e.provenance.clone(),
                })
                .collect()
        },
        project_detail: r
            .project_contents
            .iter()
            .map(|c| {
                let markers = r
                    .projects
                    .iter()
                    .find(|p| p.name == c.project)
                    .map(|p| p.markers.clone())
                    .unwrap_or_default();
                (
                    c.project.clone(),
                    (
                        markers,
                        c.roles.iter().map(|(k, v)| (k.clone(), *v)).collect(),
                    ),
                )
            })
            .collect(),
        services: {
            let mut v: Vec<stub::ServiceView> = r
                .services
                .services
                .iter()
                .filter(|s| s.name.ends_with(".service"))
                .take(150)
                .map(|s| stub::ServiceView {
                    name: s.name.clone(),
                    scope: match s.scope {
                        configctl_discovery::services::UnitScope::User => "user".into(),
                        configctl_discovery::services::UnitScope::System => "system".into(),
                    },
                    enabled: s.enabled,
                    active: s.active.clone(),
                })
                .collect();
            v.sort_by(|a, b| (&a.scope, &a.name).cmp(&(&b.scope, &b.name)));
            v
        },
        global_env: r
            .environment
            .vars
            .iter()
            .take(512)
            .map(|v| stub::GlobalEnvView {
                name: v.name.clone(),
                classification: v.classification.as_str().into(),
                value: v.value.clone(),
            })
            .collect(),
        package_versions: r
            .package_inventory
            .packages
            .iter()
            .take(20000)
            .map(|p| stub::PackageVersionView {
                manager: p.manager.clone(),
                name: p.name.clone(),
                version: p.version.clone(),
            })
            .collect(),
    }
}

/// Render a human-readable capture summary.
pub fn render_human(out: &CaptureOutput, verbose: bool) -> String {
    let mut s = String::new();
    if let Some(res) = &out.result {
        let sum = &res.summary;
        s.push_str("Capture summary\n\n");
        s.push_str(&format!("Profile:        {}\n", res.profile.name));
        s.push_str(&format!("Projects:       {}\n", sum.projects));
        s.push_str(&format!("Files:          {}\n", sum.files));
        s.push_str(&format!("Packages:       {}\n", sum.packages));
        s.push_str(&format!("Toolchains:     {}\n", sum.toolchains));
        s.push_str(&format!("Services:       {}\n", sum.services));
        s.push_str(&format!("Env literals:   {}\n", sum.env_literals));
        s.push_str(&format!("Directories:    {}\n", sum.directories));
        s.push_str(&format!("Env schemas:    {}\n", sum.env_schemas));
        s.push_str(&format!("Secrets:        {}\n", sum.secrets));
        if !sum.capture_actions.is_empty() {
            let mut actions: Vec<(&String, &u64)> = sum.capture_actions.iter().collect();
            actions.sort_by(|a, b| a.0.cmp(b.0));
            s.push_str("Capture actions:\n");
            for (action, count) in actions {
                s.push_str(&format!("  {action}: {count}\n"));
            }
        }
        s.push('\n');
        if !sum.excluded.is_empty() {
            s.push_str("Excluded:\n");
            for e in &sum.excluded {
                s.push_str(&format!("  {e}\n"));
            }
            s.push('\n');
        }
        if !sum.unsupported.is_empty() {
            s.push_str("Unsupported:\n");
            for e in &sum.unsupported {
                s.push_str(&format!("  {e}\n"));
            }
            s.push('\n');
        }
        s.push_str(&format!(
            "Redacted:\n  {} secret variables (values never stored)\n\n",
            sum.redacted
        ));
        if out.dry_run {
            s.push_str("Dry run — no files written.\n");
            s.push_str("Would write:\n");
            for w in &out.written {
                s.push_str(&format!("  {w}\n"));
            }
        } else {
            s.push_str(&format!("Wrote {}\n", out.out_dir.display()));
            if verbose {
                for w in &out.written {
                    s.push_str(&format!("  {w}\n"));
                }
            }
        }
        if !sum.warnings.is_empty() && verbose {
            s.push_str("\nWarnings:\n");
            for w in &sum.warnings {
                s.push_str(&format!("  {w}\n"));
            }
        }
    } else {
        s.push_str("Capture failed.\n");
    }
    s
}
