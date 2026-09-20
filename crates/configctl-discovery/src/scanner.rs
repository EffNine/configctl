//! The scan service: SCAN → DISCOVER → CLASSIFY → REDACT → REPORT.
//!
//! Composes the walker, project/env/config detectors, git tracking, and
//! system metadata into a single read-only pass. No mutation.

use crate::config::{self, ConfigFileRecord};
use crate::env::{self, EnvFileRecord, GitStatus};
use crate::git;
use crate::packages::{self, PackageInventory};
use crate::project::{self, ProjectDetection};
use crate::secret::{self, EntropyScorer};
use crate::system::{self, SystemInfo};
use crate::toolchain::{self, ToolchainInventory};
use crate::walker::{BoundedWalker, StopReason, Visit};
use configctl_core::command::CommandRunner;
use configctl_core::governor::{GovernorBudgets, GovernorSnapshot, ResourceGovernor};
use configctl_core::limits::Limits;
use configctl_core::redact::SecretRegistry;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Options for a scan.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub roots: Vec<PathBuf>,
    pub limits: Limits,
    /// v1.1 central budgets (defaults when unset at a construction site).
    pub governor: GovernorBudgets,
}

/// Aggregated walk stats across all roots.
#[derive(Debug, Default, Clone)]
struct WalkStats {
    files: usize,
    directories: usize,
    permission_denied: usize,
    excluded: usize,
    depth_reached: usize,
    stop_reasons: Vec<String>,
}

/// The full scan result (redaction-safe view; values never stored).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(default)]
pub struct ScanResult {
    pub schema_version: u32,
    pub timestamp: String,
    pub system: SystemInfo,
    pub roots: Vec<String>,
    pub projects: Vec<ProjectRecord>,
    pub env_files: Vec<EnvFileRecord>,
    pub config_files: Vec<ConfigFileRecord>,
    pub git_findings: Vec<GitFinding>,
    pub warnings: Vec<String>,
    pub statistics: ScanStats,
    /// v1.1 governor snapshot (budgets consumed, limit hit, pressure).
    pub governor: GovernorSnapshot,
    /// v1.1 package ecosystem inventory (capped lists + complete counts).
    #[serde(default)]
    pub package_inventory: PackageInventory,
    /// v1.1 toolchain inventory (capped lists + complete counts).
    #[serde(default)]
    pub toolchain: ToolchainInventory,
}

impl ScanResult {
    /// Build a redacted JSON string: serialize, then run the redaction layer
    /// over the entire document.
    pub fn redacted_json(
        &self,
        registry: &std::sync::Arc<SecretRegistry>,
        patterns: &[(&str, &str)],
    ) -> String {
        let raw = serde_json::to_string(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
        configctl_core::redact::redact_with_patterns(registry, &raw, patterns)
    }
}

/// A discovered project.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectRecord {
    pub path: String,
    pub name: String,
    pub markers: Vec<String>,
    pub vcs: String,
    pub hints: Vec<String>,
    pub confidence: String,
    pub warnings: Vec<String>,
}

/// A git-related finding (tracked `.env`, etc.).
#[derive(Debug, Clone, serde::Serialize)]
pub struct GitFinding {
    pub path: String,
    pub status: String,
    pub risk: String,
}

/// Scan statistics.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(default)]
pub struct ScanStats {
    pub projects_found: usize,
    pub env_files_found: usize,
    pub config_files_found: usize,
    pub secret_variables: usize,
    pub likely_secret_variables: usize,
    pub tracked_env_files: usize,
    pub warnings: usize,
    pub permission_denied: usize,
    pub excluded_paths: usize,
    pub files_visited: usize,
    pub stop_reasons: Vec<String>,
    /// v1.1: packages observed across all managers.
    pub packages_found: usize,
    /// v1.1: executables discovered on PATH.
    pub executables_found: usize,
}

/// The scan service.
pub struct Scanner {
    registry: std::sync::Arc<SecretRegistry>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            registry: std::sync::Arc::new(SecretRegistry::default()),
        }
    }

    pub fn registry(&self) -> &std::sync::Arc<SecretRegistry> {
        &self.registry
    }

    /// Run the full scan. Read-only.
    pub fn scan(&mut self, opts: &ScanOptions, runner: &dyn CommandRunner) -> ScanResult {
        let limits = &opts.limits;
        let roots = &opts.roots;
        let registry = self.registry();
        // v1.1: one central governor for the whole scan.
        let governor = ResourceGovernor::new(opts.governor.clone());

        // 1. System metadata
        let scratch = std::env::temp_dir();
        let system = system::collect(runner, &scratch);

        let mut warnings: Vec<String> = Vec::new();
        let mut walk_stats_total = WalkStats::default();

        // Existing roots only; never the whole filesystem.
        let existing_roots: Vec<PathBuf> = roots.iter().filter(|p| p.exists()).cloned().collect();
        let missing: Vec<String> = roots
            .iter()
            .filter(|p| !p.exists())
            .map(|p| p.display().to_string())
            .collect();
        for m in &missing {
            warnings.push(format!("scan root does not exist: {m}"));
        }

        // 2. Discover: walk each root, collect candidate files.
        let mut project_dirs: BTreeMap<String, PathBuf> = BTreeMap::new();
        let mut env_paths: BTreeMap<String, PathBuf> = BTreeMap::new();
        let mut config_paths: BTreeMap<String, PathBuf> = BTreeMap::new();

        let mut any_walked = false;
        for root in &existing_roots {
            let walker =
                BoundedWalker::new(limits.clone()).with_governor(std::sync::Arc::clone(&governor));
            let mut collector = |visit: &Visit| {
                collect_visit(visit, &mut project_dirs, &mut env_paths, &mut config_paths);
                true
            };
            let stats = walker.walk(root, &mut collector);
            any_walked = true;

            walk_stats_total.files += stats.files;
            walk_stats_total.directories += stats.directories;
            walk_stats_total.permission_denied += stats.permission_denied;
            walk_stats_total.excluded += stats.excluded;
            if let Some(reason) = stats.stop_reason {
                walk_stats_total
                    .stop_reasons
                    .push(reason.as_str().to_string());
            }
            if let Some(gov_reason) = stats.governor_limit {
                // Explicit budget identity for the completeness report.
                walk_stats_total
                    .stop_reasons
                    .push(format!("governor:{gov_reason}"));
            }
            if stats.permission_denied > 0 {
                walk_stats_total
                    .stop_reasons
                    .push("permission_denied".to_string());
            }
            walk_stats_total.depth_reached =
                walk_stats_total.depth_reached.max(stats.depth_reached);
        }
        // Diagnostics: surface unreadable paths in the result.
        if walk_stats_total.permission_denied > 0 {
            warnings.push(format!(
                "{} path(s) unreadable (permission denied)",
                walk_stats_total.permission_denied
            ));
        }
        // Report the depth limit even when the walk terminated before visiting
        // any file (tree deeper than max_depth).
        if any_walked && walk_stats_total.stop_reasons.is_empty() {
            for root in &existing_roots {
                if max_tree_depth(root, limits.max_depth + 1) > limits.max_depth {
                    walk_stats_total
                        .stop_reasons
                        .push(StopReason::DepthLimit.as_str().to_string());
                    break;
                }
            }
        }

        // Cap env/config paths to the finding limit to bound work.
        let mut env_list: Vec<&Path> = env_paths.values().map(|p| p.as_path()).collect();
        env_list.truncate(limits.max_findings);
        let mut config_list: Vec<&Path> = config_paths.values().map(|p| p.as_path()).collect();
        config_list.truncate(limits.max_findings);

        // 3. Project detection
        let mut projects: Vec<ProjectRecord> = project_dirs
            .values()
            .filter_map(|dir| {
                let det: ProjectDetection = project::detect_project(dir);
                if !det.is_project() {
                    return None;
                }
                let name = dir
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let vcs = match det.vcs {
                    crate::project::VcsType::Git => "git",
                    crate::project::VcsType::Unknown => "unknown",
                };
                let mut proj_warnings = Vec::new();
                if det.markers_first_is_git() {
                    proj_warnings.push("bare VCS marker only; no project manifest found".into());
                }
                Some(ProjectRecord {
                    path: dir.to_string_lossy().into_owned(),
                    name,
                    markers: det.markers_found.clone(),
                    vcs: vcs.to_string(),
                    hints: det.hints.clone(),
                    confidence: det.confidence().to_string(),
                    warnings: proj_warnings,
                })
            })
            .collect();
        projects.sort_by(|a, b| a.path.cmp(&b.path));

        // 4. Git tracking detection for env + config files
        let all_files: Vec<&Path> = {
            let mut v: BTreeMap<String, &Path> = BTreeMap::new();
            for f in env_list.iter() {
                v.insert(f.to_string_lossy().into_owned(), f);
            }
            for f in config_list.iter() {
                v.entry(f.to_string_lossy().into_owned()).or_insert(f);
            }
            v.into_values().collect()
        };

        let mut git_map: BTreeMap<String, GitStatus> = BTreeMap::new();
        for f in &all_files {
            let dir = f.parent().unwrap_or_else(|| Path::new("."));
            if let Some(root) = git::git_root_for_dir(runner, dir) {
                let fbuf: PathBuf = f.to_path_buf();
                let status = git::check_tracking(runner, &root, std::slice::from_ref(&fbuf));
                git_map.extend(status);
            }
        }

        // 5. Process env files
        let mut env_records: Vec<EnvFileRecord> = Vec::new();
        let mut secret_total = 0usize;
        let mut likely_total = 0usize;
        let mut tracked_env = 0usize;

        for f in &env_list {
            let path_str = f.to_string_lossy().into_owned();
            let git_status = git_map
                .get(&path_str)
                .copied()
                .unwrap_or(GitStatus::Unknown);
            if git_status == GitStatus::Tracked {
                tracked_env += 1;
                warnings.push(format!("WARNING: .env file tracked by Git: {path_str}"));
            }
            match env::process_env_file(f, limits, git_status, registry.as_ref()) {
                Ok(mut rec) => {
                    rec.project = find_project_of(&path_str, &projects);
                    secret_total += rec.secret_count;
                    likely_total += rec.likely_secret_count;
                    env_records.push(rec);
                }
                Err(e) => {
                    let redacted = registry.redact(&e);
                    warnings.push(format!("env file error: {redacted}"));
                }
            }
        }
        env_records.sort_by(|a, b| a.path.cmp(&b.path));

        // 6. Process config files
        let mut config_records: Vec<ConfigFileRecord> = Vec::new();
        for f in &config_list {
            let path_str = f.to_string_lossy().into_owned();
            let git_status = git_map
                .get(&path_str)
                .copied()
                .unwrap_or(GitStatus::Unknown);
            match config::process_config_file(f, limits, git_status) {
                Ok(mut rec) => {
                    rec.project = find_project_of(&path_str, &projects);
                    config_records.push(rec);
                }
                Err(e) => {
                    let redacted = registry.redact(&e);
                    warnings.push(format!("config file error: {redacted}"));
                }
            }
        }
        config_records.sort_by(|a, b| a.path.cmp(&b.path));

        // 7. Git findings: tracked env files are high-risk
        let mut git_findings: Vec<GitFinding> = Vec::new();
        for rec in &env_records {
            if rec.tracked_by_git == GitStatus::Tracked {
                git_findings.push(GitFinding {
                    path: rec.path.clone(),
                    status: "TRACKED".into(),
                    risk: "HIGH".into(),
                });
            }
        }

        // 8. v1.1 package + toolchain provenance. Runs after git tracking so
        //    canned test outputs are consumed by their intended probes first.
        //    Every probe is governor-bounded; failures are recorded, never fatal.
        let mut package_inventory = packages::collect_packages(&governor, runner);
        let mut toolchain_inv = toolchain::discover_executables(&governor, runner);
        // Bound report size: counts stay complete, lists truncate explicitly.
        if toolchain_inv.executables.len() > 5000 {
            toolchain_inv.executables.truncate(5000);
            toolchain_inv.truncated = true;
            toolchain_inv
                .warnings
                .push("executable report list truncated to 5000 entries".into());
        }
        warnings.extend(package_inventory.warnings.iter().cloned());
        warnings.extend(toolchain_inv.warnings.iter().cloned());
        if let Some(hit) = governor.limit_hit() {
            warnings.push(format!("governor budget exhausted: {hit}"));
        }

        // 8. Diagnostics (kept for future use; silence unused warnings)
        let _scorer = EntropyScorer::default();
        let _ = secret::NAME_LEXICON;

        let files_visited = walk_stats_total.files + walk_stats_total.directories;
        let mut stop_reasons = walk_stats_total.stop_reasons.clone();
        stop_reasons.sort();
        stop_reasons.dedup();

        let mut stats = ScanStats {
            projects_found: projects.len(),
            env_files_found: env_records.len(),
            config_files_found: config_records.len(),
            secret_variables: secret_total,
            likely_secret_variables: likely_total,
            tracked_env_files: tracked_env,
            warnings: warnings.len(),
            permission_denied: walk_stats_total.permission_denied,
            excluded_paths: walk_stats_total.excluded,
            files_visited,
            stop_reasons,
            packages_found: package_inventory.total,
            executables_found: toolchain_inv.total,
        };

        let timestamp = rfc3339_now();

        if projects.len() > limits.max_findings {
            projects.truncate(limits.max_findings);
            stats.projects_found = projects.len();
        }

        let mut root_strings: Vec<String> = roots
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        root_strings.sort();
        root_strings.dedup();

        ScanResult {
            schema_version: 1,
            timestamp,
            system,
            roots: root_strings,
            projects,
            env_files: env_records,
            config_files: config_records,
            git_findings,
            warnings,
            statistics: stats,
            governor: governor.snapshot(),
            package_inventory,
            toolchain: toolchain_inv,
        }
    }
}

/// Collect file-class candidates from one visited path.
fn collect_visit(
    visit: &Visit,
    project_dirs: &mut BTreeMap<String, PathBuf>,
    env_paths: &mut BTreeMap<String, PathBuf>,
    config_paths: &mut BTreeMap<String, PathBuf>,
) {
    let path = &visit.path;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    if name == ".git" {
        if let Some(parent) = path.parent() {
            let key = parent.to_string_lossy().into_owned();
            project_dirs
                .entry(key)
                .or_insert_with(|| parent.to_path_buf());
        }
    }
    if project::MARKERS.iter().any(|m| m.name == name && !m.is_dir) {
        if let Some(parent) = path.parent() {
            let key = parent.to_string_lossy().into_owned();
            project_dirs
                .entry(key)
                .or_insert_with(|| parent.to_path_buf());
        }
    }
    if env::is_env_filename(&name) {
        let key = path.to_string_lossy().into_owned();
        env_paths.entry(key).or_insert_with(|| path.clone());
    }
    if config::match_config_type(&name) {
        let key = path.to_string_lossy().into_owned();
        config_paths.entry(key).or_insert_with(|| path.clone());
    }
}

/// Probe how deep the tree under `root` actually goes (bounded by
/// `probe_max` so we never walk a huge tree just to measure it).
fn max_tree_depth(root: &Path, probe_max: usize) -> usize {
    let walker = BoundedWalker::new(Limits {
        max_depth: probe_max,
        ..Limits::default()
    });
    let stats = walker.walk(root, &mut |_| true);
    stats.depth_reached
}

/// Find the project (by prefix) that owns a path.
fn find_project_of(path_str: &str, projects: &[ProjectRecord]) -> Option<String> {
    for p in projects {
        if path_str.starts_with(&p.path) {
            return Some(p.name.clone());
        }
    }
    None
}

/// RFC 3339 current timestamp (UTC).
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
