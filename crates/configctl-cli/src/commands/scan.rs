//! `configctl scan` — read-only discovery.

use crate::render::Envelope;
use configctl_core::command::CommandRunner;
use configctl_core::governor::{GovernorBudgets, parse_bytes, parse_duration};
use configctl_core::limits::Limits;
use configctl_discovery::scanner::{ScanOptions, ScanResult, Scanner};
use std::path::{Path, PathBuf};

/// Result of running the scan command.
pub struct ScanOutput {
    pub result: ScanResult,
    pub error_envelope: Option<Envelope>,
    /// The redaction registry populated during the scan; callers use it to
    /// redact every sink (human + JSON) before output.
    pub registry: std::sync::Arc<configctl_core::redact::SecretRegistry>,
}

/// Default project roots (conservative, explicit, only scanned if they exist).
pub fn default_roots(home: Option<&Path>) -> Vec<PathBuf> {
    let home = match home {
        Some(h) => h.to_path_buf(),
        None => return Vec::new(),
    };
    ["projects", "src", "workspace", "work"]
        .iter()
        .map(|sub| home.join(sub))
        .collect()
}

/// Expand `~` and `~/...` prefixes in a root path string.
pub fn expand_root(raw: &str, home: &Path) -> PathBuf {
    if raw == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return home.join(rest);
    }
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        p
    } else {
        match std::env::current_dir() {
            Ok(c) => c.join(p),
            Err(_) => p,
        }
    }
}

/// v1.1 resource-control flags shared by `scan` and `capture`.
#[derive(Debug, Clone, Default)]
pub struct ScanGovernorFlags {
    pub workers: Option<usize>,
    pub max_time: Option<String>,
    pub max_files: Option<u64>,
    pub max_bytes: Option<String>,
    pub max_memory: Option<String>,
    pub follow_mounts: bool,
    pub scan_network: bool,
}

/// Build sanitized governor budgets from CLI flags. Every value passes
/// through hard sanity ceilings — even explicit overrides cannot request
/// dangerous budgets.
pub fn governor_from_flags(flags: &ScanGovernorFlags) -> Result<GovernorBudgets, String> {
    let mut b = GovernorBudgets::default();
    if let Some(w) = flags.workers {
        b.max_workers = w;
    }
    if let Some(raw) = &flags.max_time {
        b.max_wall_time = parse_duration(raw)?;
    }
    if let Some(n) = flags.max_files {
        b.max_file_count = n;
    }
    if let Some(raw) = &flags.max_bytes {
        b.max_total_bytes_read = parse_bytes(raw)?;
    }
    if let Some(raw) = &flags.max_memory {
        b.max_memory_bytes = parse_bytes(raw)?;
    }
    b.follow_mounts = flags.follow_mounts;
    b.scan_network_mounts = flags.scan_network;
    Ok(b.sanitize())
}

/// Run the scan command. Rendering (json/quiet/verbose) happens in main;
/// this function returns the raw result + redaction registry + any usage error.
pub fn run_scan(
    cli_roots: &[String],
    extra_roots: &[String],
    depth: Option<usize>,
    _json: bool,
    _quiet: bool,
    _verbose: bool,
    runner: &dyn CommandRunner,
) -> ScanOutput {
    run_scan_with_governor(
        cli_roots,
        extra_roots,
        depth,
        GovernorBudgets::default(),
        runner,
    )
}

/// Governor-aware scan entry point (v1.1).
pub fn run_scan_with_governor(
    cli_roots: &[String],
    extra_roots: &[String],
    depth: Option<usize>,
    governor: GovernorBudgets,
    runner: &dyn CommandRunner,
) -> ScanOutput {
    let home = dirs::home_dir();
    let limits = Limits::default();
    let limits = match depth {
        Some(d) => Limits {
            max_depth: d,
            ..limits
        },
        None => limits,
    };

    // Collect roots: CLI positionals + extra --root flags + defaults.
    let mut roots: Vec<PathBuf> = Vec::new();
    let h = home.as_deref();
    for r in cli_roots {
        if let Some(h) = h {
            roots.push(expand_root(r, h));
        } else {
            roots.push(PathBuf::from(r));
        }
    }
    for r in extra_roots {
        if let Some(h) = h {
            roots.push(expand_root(r, h));
        } else {
            roots.push(PathBuf::from(r));
        }
    }
    if roots.is_empty() {
        let defaults = default_roots(h);
        if !defaults.is_empty() {
            roots.extend(defaults);
        }
    }

    // Deduplicate while preserving order.
    {
        let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
        roots.retain(|p| seen.insert(p.clone()));
    }

    if roots.is_empty() {
        let err = Envelope::error(
            "scan",
            "no scan roots provided",
            "Pass one or more paths: configctl scan ~/projects, or set scan.roots in config.toml.",
        );
        return ScanOutput {
            result: unsafe_result(),
            error_envelope: Some(err),
            registry: std::sync::Arc::new(configctl_core::redact::SecretRegistry::default()),
        };
    }

    let opts = ScanOptions {
        roots: roots.clone(),
        limits,
        governor,
    };

    let mut scanner = Scanner::new();
    let result = scanner.scan(&opts, runner);
    let registry = scanner.registry().clone();
    ScanOutput {
        result,
        error_envelope: None,
        registry,
    }
}

fn unsafe_result() -> ScanResult {
    ScanResult {
        schema_version: 1,
        timestamp: String::new(),
        system: Default::default(),
        roots: Vec::new(),
        projects: Vec::new(),
        env_files: Vec::new(),
        config_files: Vec::new(),
        git_findings: Vec::new(),
        warnings: Vec::new(),
        statistics: Default::default(),
        governor: Default::default(),
        package_inventory: Default::default(),
        toolchain: Default::default(),
    }
}

/// Render the scan result as a human-readable report.
pub fn render_human(result: &ScanResult, quiet: bool, verbose: bool) -> String {
    let mut out = String::new();
    if !quiet {
        out.push_str("configctl scan\n\n");
        out.push_str(&format!(
            "System\n  {}\n  {}\n",
            distro_line(&result.system),
            result.system.arch
        ));
        out.push_str(&format!("  git: {}\n", tool_line(&result.system, "git")));
        out.push('\n');
    }

    let s = &result.statistics;
    if !quiet {
        out.push_str(&format!("Projects\n  {} discovered\n\n", s.projects_found));
        out.push_str(&format!(
            "Environment files\n  {} discovered\n  {} contain likely secrets\n  {} tracked by Git\n\n",
            s.env_files_found,
            s.likely_secret_variables + s.secret_variables,
            s.tracked_env_files
        ));
        out.push_str(&format!(
            "Config files\n  {} discovered\n\n",
            s.config_files_found
        ));
        out.push_str(&format!(
            "Packages\n  {} observed across {} managers\n\n",
            s.packages_found,
            result.package_inventory.managers.iter().filter(|m| m.available).count()
        ));
        out.push_str(&format!(
            "Executables\n  {} discovered on PATH ({} version-probed)\n\n",
            s.executables_found, result.toolchain.version_probed
        ));
    }

    if s.warnings > 0 || !result.warnings.is_empty() {
        out.push_str("Warnings\n");
        let unique: Vec<&String> = result.warnings.iter().collect();
        for w in &unique {
            out.push_str(&format!("  {w}\n"));
        }
    }

    if verbose {
        out.push_str("\nDetails\n");
        for p in &result.projects {
            out.push_str(&format!(
                "  project {} ({}) [{}]\n",
                p.name, p.path, p.confidence
            ));
        }
        for e in &result.env_files {
            out.push_str(&format!(
                "  env {} [{} vars, {} secrets] git:{}\n",
                e.path,
                e.variable_count,
                e.secret_count + e.likely_secret_count,
                e.tracked_by_git.as_str()
            ));
        }
        for c in &result.config_files {
            out.push_str(&format!("  config {}\n", c.path));
        }
    }

    out.push_str("\nNo changes made.\n");
    // v1.1 governor footer: always visible so bounded scans are observable.
    let g = &result.governor;
    match &g.limit_hit {
        Some(reason) => out.push_str(&format!(
            "Governor: PARTIAL (budget exhausted: {reason}; files {} bytes {} subprocesses {})\n",
            g.files, g.bytes_read, g.subprocesses_total
        )),
        None => out.push_str(&format!(
            "Governor: ok (files {} bytes {} subprocesses {} in {}s)\n",
            g.files, g.bytes_read, g.subprocesses_total, g.elapsed_secs
        )),
    }
    out
}

fn distro_line(system: &configctl_discovery::SystemInfo) -> String {
    match &system.distro {
        Some(d) => d.clone(),
        None => "Linux".into(),
    }
}

fn tool_line(system: &configctl_discovery::SystemInfo, tool: &str) -> String {
    if system.has(tool) {
        match system.details.get(tool).and_then(|t| t.version.as_deref()) {
            Some(v) => format!("available ({v})"),
            None => "available".into(),
        }
    } else {
        "unavailable".into()
    }
}
