//! `configctl scan` — read-only discovery.

use crate::render::Envelope;
use configctl_core::command::CommandRunner;
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
