//! The scan service: SCAN → DISCOVER → CLASSIFY → REDACT → REPORT.
//!
//! Composes the walker, project/env/config detectors, git tracking, and
//! system metadata into a single read-only pass. No mutation.

use crate::config::{self, ConfigFileRecord};
use crate::credentials::{self, CredentialInventory};
use crate::env::{self, EnvFileRecord, GitStatus};
use crate::environment::{self, EnvironmentInventory};
use crate::filesystem::{
    categorize_dotfile, classify_project_file, DotfileRecord, ProjectContentSummary,
};
use crate::git;
use crate::hardware::{self, HardwareInventory};
use crate::inventory::InventoryCollector;
use crate::mounts::{self, MountRecord};
use crate::packages::{self, PackageInventory};
use crate::project::{self, ProjectDetection};
use crate::secret::{self, EntropyScorer};
use crate::services::{self, ServiceInventory};
use crate::system::{self, SystemInfo};
use crate::toolchain::{self, ToolchainInventory};
use crate::walker::{BoundedWalker, StopReason, Visit};
use configctl_core::classify::{classify_file, FileKind};
use configctl_core::command::CommandRunner;
use configctl_core::governor::{GovernorBudgets, GovernorSnapshot, ResourceGovernor};
use configctl_core::inventory::{CompletenessReport, InventoryCounters, SymlinkRecord};
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
    symlinks_seen: u64,
    special_seen: u64,
    denied_prunes: u64,
    mount_boundaries: u64,
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
    /// v1.1 filesystem summary: counters + classification histogram.
    #[serde(default)]
    pub filesystem: FilesystemSummary,
    /// v1.1 dotfiles (capped list; total in [`FilesystemSummary`]).
    #[serde(default)]
    pub dotfiles: Vec<DotfileRecord>,
    /// v1.1 per-project content roles (counts, never silent).
    #[serde(default)]
    pub project_contents: Vec<ProjectContentSummary>,
    /// v1.1 mount table (recorded boundaries, not just traversed paths).
    #[serde(default)]
    pub mounts: Vec<MountRecord>,
    /// v1.1 scan completeness (observed / mapped / skipped + reasons).
    #[serde(default)]
    pub completeness: CompletenessReport,
    /// v1.1 systemd units (user + system, read-only).
    #[serde(default)]
    pub services: ServiceInventory,
    /// v1.1 process environment map (metadata only, never values).
    #[serde(default)]
    pub environment: EnvironmentInventory,
    /// v1.1 hardware / system context (informational).
    #[serde(default)]
    pub hardware: HardwareInventory,
    /// v1.1 SSH / GPG / cloud credential metadata (never material).
    #[serde(default)]
    pub credentials: CredentialInventory,
}

/// v1.1 filesystem summary.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FilesystemSummary {
    pub counters: InventoryCounters,
    /// `classification → count` for regular files.
    pub classes: BTreeMap<String, u64>,
    pub dotfiles_found: usize,
    pub dotfiles_truncated: bool,
    /// Mapped symlink relationships (capped; overflow counted).
    pub symlinks: Vec<SymlinkRecord>,
    pub symlinks_truncated: bool,
    pub symlinks_overflow: u64,
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
    /// v1.1: symlinks mapped (never followed).
    pub symlinks_found: usize,
    /// v1.1: dotfiles discovered.
    pub dotfiles_found: usize,
    /// v1.1: systemd units observed.
    pub services_found: usize,
    /// v1.1: environment variables mapped (metadata only).
    pub env_vars_found: usize,
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
        let system = system::collect(&governor, runner, &scratch);

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
        // v1.1: every visit is also classified into the inventory; symlinks
        // and special files are mapped, never followed or opened.
        let mut walk = WalkCollector::new();

        let mut any_walked = false;
        for root in &existing_roots {
            walk.collector.set_scan_root(root.clone());
            let walker =
                BoundedWalker::new(limits.clone()).with_governor(std::sync::Arc::clone(&governor));
            let mut collector = |visit: &Visit| {
                walk.collect_visit(visit);
                true
            };
            let stats = walker.walk(root, &mut collector);
            any_walked = true;

            walk_stats_total.files += stats.files;
            walk_stats_total.directories += stats.directories;
            walk_stats_total.permission_denied += stats.permission_denied;
            walk_stats_total.excluded += stats.excluded;
            walk_stats_total.symlinks_seen += stats.symlinks_seen;
            walk_stats_total.special_seen += stats.special_seen;
            walk_stats_total.denied_prunes += stats.denied_prunes;
            walk_stats_total.mount_boundaries += stats.mount_boundaries;
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
            if stats.mount_boundaries > 0 {
                walk_stats_total
                    .stop_reasons
                    .push("mount_boundary".to_string());
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
        let mut env_list: Vec<&Path> = walk.env_paths.values().map(|p| p.as_path()).collect();
        env_list.truncate(limits.max_findings);
        let mut config_list: Vec<&Path> = walk.config_paths.values().map(|p| p.as_path()).collect();
        config_list.truncate(limits.max_findings);

        // 3. Project detection
        let mut projects: Vec<ProjectRecord> = walk
            .project_dirs
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
                    crate::project::VcsType::Mercurial => "hg",
                    crate::project::VcsType::Subversion => "svn",
                    crate::project::VcsType::Jujutsu => "jj",
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
        let package_inventory = packages::collect_packages(&governor, runner);
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

        // 8b. v1.1 services, environment, hardware, credentials. All
        //     governor-bounded; unavailable sources are recorded, never fatal.
        //     Mounts are discovered before traversal-dependent steps so the
        //     hardware inventory can resolve the root filesystem.
        let mount_records = mounts::collect();
        let service_inventory = services::collect_services(&governor, runner);
        warnings.extend(service_inventory.warnings.iter().cloned());
        let environment_inventory = environment::collect_environment();
        let home_dir = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let credential_inventory =
            credentials::collect_credentials(&governor, runner, home_dir.as_deref());
        warnings.extend(credential_inventory.warnings.iter().cloned());
        let compilers: Vec<String> = toolchain_inv
            .executables
            .iter()
            .filter(|e| {
                matches!(
                    e.name.as_str(),
                    "gcc" | "g++" | "clang" | "clang++" | "rustc" | "go" | "javac" | "cc" | "c++"
                )
            })
            .map(|e| {
                e.version
                    .as_deref()
                    .map(|v| format!("{} ({v})", e.name))
                    .unwrap_or_else(|| e.name.clone())
            })
            .collect();
        let hardware_inventory =
            hardware::collect_hardware(&governor, runner, &mount_records, compilers);

        // 9. v1.1 filesystem summary, project content roles, mounts,
        //    and the completeness report.
        let project_contents = summarize_project_contents(&projects, &walk.visited);
        if walk.visited_overflow > 0 {
            warnings.push(format!(
                "project content mapping truncated: {} file(s) beyond buffer not role-mapped",
                walk.visited_overflow
            ));
        }
        if walk_stats_total.mount_boundaries > 0 {
            warnings.push(format!(
                "{} mount boundar(ies) recorded, not descended (see `mounts`)",
                walk_stats_total.mount_boundaries
            ));
        }

        let filesystem = FilesystemSummary {
            counters: walk.collector.counters().clone(),
            classes: walk.collector.class_counts().clone(),
            dotfiles_found: walk.dotfiles_total,
            dotfiles_truncated: walk.dotfiles_truncated,
            symlinks: walk.collector.symlinks().to_vec(),
            symlinks_truncated: walk.collector.symlinks_truncated(),
            symlinks_overflow: walk.collector.symlinks_overflow(),
        };
        let dotfiles = std::mem::take(&mut walk.dotfiles);

        let mut completeness = walk.collector.completeness().clone();
        if walk_stats_total.permission_denied > 0 {
            completeness.record_skip(
                "permission_denied",
                walk_stats_total.permission_denied as u64,
            );
        }
        if walk_stats_total.mount_boundaries > 0 {
            completeness.record_skip("external_mount", walk_stats_total.mount_boundaries);
        }
        let specials = filesystem.counters.sockets
            + filesystem.counters.fifos
            + filesystem.counters.devices
            + filesystem.counters.unknown_types;
        if specials > 0 {
            completeness.record_skip("special_file", specials);
        }
        if walk_stats_total.denied_prunes > 0 {
            completeness.record_skip("policy_pruned", walk_stats_total.denied_prunes);
        }
        if governor.limit_hit().is_some() {
            completeness.record_skip("budget_exhausted", 1);
        }
        // v1 traversal limits are budgets too: a depth/file/byte/finding
        // stop means the scan did not see everything — PARTIAL, named.
        for reason in &walk_stats_total.stop_reasons {
            match reason.as_str() {
                "depth_limit" | "file_count_limit" | "byte_limit" | "finding_limit"
                | "governor_limit" => {
                    completeness.record_skip(&format!("limit:{reason}"), 1);
                }
                _ => {}
            }
        }
        // Observed = everything the scan encountered (mapped + skipped);
        // without this, a budget-stopped scan would still read 100%.
        completeness.observed = completeness.mapped + completeness.skipped;
        completeness.finalize(governor.limit_hit().is_some());

        // 10. Diagnostics (kept for future use; silence unused warnings)
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
            symlinks_found: filesystem.counters.symlinks as usize,
            dotfiles_found: filesystem.dotfiles_found,
            services_found: service_inventory.services.len(),
            env_vars_found: environment_inventory.total,
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
            filesystem,
            dotfiles,
            project_contents,
            mounts: mount_records,
            completeness,
            services: service_inventory,
            environment: environment_inventory,
            hardware: hardware_inventory,
            credentials: credential_inventory,
        }
    }
}

/// Directory markers that identify a project root on their own.
const DIR_MARKERS: &[&str] = &[".git", ".hg", ".svn", ".jj", ".github", ".vscode", ".cargo"];

/// Maximum regular files buffered for project content mapping.
const MAX_VISITED_FILES: usize = 100_000;
/// Maximum dotfile records retained in the report.
const MAX_DOTFILES: usize = 2000;

/// Per-walk collection state: legacy candidate maps plus the v1.1
/// inventory, visited-file buffer, and dotfile records.
struct WalkCollector {
    project_dirs: BTreeMap<String, PathBuf>,
    env_paths: BTreeMap<String, PathBuf>,
    config_paths: BTreeMap<String, PathBuf>,
    collector: InventoryCollector,
    /// (path, size, executable) for regular files, bounded.
    visited: Vec<(PathBuf, u64, bool)>,
    visited_overflow: u64,
    dotfiles: Vec<DotfileRecord>,
    dotfiles_total: usize,
    dotfiles_truncated: bool,
}

impl WalkCollector {
    fn new() -> Self {
        Self {
            project_dirs: BTreeMap::new(),
            env_paths: BTreeMap::new(),
            config_paths: BTreeMap::new(),
            collector: InventoryCollector::new(),
            visited: Vec::new(),
            visited_overflow: 0,
            dotfiles: Vec::new(),
            dotfiles_total: 0,
            dotfiles_truncated: false,
        }
    }

    /// Collect candidates from one visit. Symlinks and special files are
    /// mapped into the inventory only — their content is never read and
    /// they never seed env/config/project candidates (no escape).
    fn collect_visit(&mut self, visit: &Visit) {
        let path = &visit.path;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        let size_opt = if visit.kind == FileKind::Regular {
            Some(visit.size)
        } else {
            None
        };
        self.collector
            .observe_typed(path, visit.kind, size_opt, visit.executable);

        match visit.kind {
            FileKind::Directory => {
                if DIR_MARKERS.iter().any(|m| *m == name) {
                    if let Some(parent) = path.parent() {
                        let key = parent.to_string_lossy().into_owned();
                        self.project_dirs
                            .entry(key)
                            .or_insert_with(|| parent.to_path_buf());
                    }
                }
                return;
            }
            FileKind::Regular => {}
            // Symlinks / specials / unknown: mapped, never content-read.
            _ => return,
        }

        if self.visited.len() < MAX_VISITED_FILES {
            self.visited
                .push((path.clone(), visit.size, visit.executable));
        } else {
            self.visited_overflow += 1;
        }

        // Broad dotfile discovery: any dotfile, categorized + classified.
        if name.starts_with('.') {
            self.dotfiles_total += 1;
            if self.dotfiles.len() < MAX_DOTFILES {
                let c = classify_file(path, FileKind::Regular, visit.executable);
                self.dotfiles.push(DotfileRecord {
                    path: path.to_string_lossy().into_owned(),
                    category: categorize_dotfile(&name).to_string(),
                    classification: c.class,
                    action: c.action,
                    signals: c.signals,
                    reason: c.reason,
                    name: name.clone(),
                });
            } else {
                self.dotfiles_truncated = true;
            }
        }

        // Legacy candidate matching (regular files only).
        if name == ".git" {
            // `.git` file (worktree/submodule pointer).
            if let Some(parent) = path.parent() {
                let key = parent.to_string_lossy().into_owned();
                self.project_dirs
                    .entry(key)
                    .or_insert_with(|| parent.to_path_buf());
            }
        }
        if project::MARKERS.iter().any(|m| m.name == name && !m.is_dir) {
            if let Some(parent) = path.parent() {
                let key = parent.to_string_lossy().into_owned();
                self.project_dirs
                    .entry(key)
                    .or_insert_with(|| parent.to_path_buf());
            }
        }
        if env::is_env_filename(&name) {
            let key = path.to_string_lossy().into_owned();
            self.env_paths.entry(key).or_insert_with(|| path.clone());
        }
        if config::match_config_type(&name) {
            let key = path.to_string_lossy().into_owned();
            self.config_paths.entry(key).or_insert_with(|| path.clone());
        }
    }
}

/// Aggregate visited files into per-project role counts. Files outside any
/// detected project are ignored here (they remain in the filesystem
/// inventory with their own classifications).
fn summarize_project_contents(
    projects: &[ProjectRecord],
    visited: &[(PathBuf, u64, bool)],
) -> Vec<ProjectContentSummary> {
    // Deepest project root first so nested projects own their files.
    let mut roots: Vec<&ProjectRecord> = projects.iter().collect();
    roots.sort_by_key(|b| std::cmp::Reverse(b.path.len()));
    let mut summaries: BTreeMap<String, ProjectContentSummary> = BTreeMap::new();
    for (path, size, executable) in visited {
        let path_str = path.to_string_lossy();
        let owner = roots.iter().find(|p| path_str.starts_with(p.path.as_str()));
        let Some(owner) = owner else { continue };
        let summary =
            summaries
                .entry(owner.path.clone())
                .or_insert_with(|| ProjectContentSummary {
                    project: owner.name.clone(),
                    path: owner.path.clone(),
                    roles: BTreeMap::new(),
                    total: 0,
                });
        let (role, _signals) = classify_project_file(path, *executable, *size);
        *summary.roles.entry(role.as_str().to_string()).or_insert(0) += 1;
        summary.total += 1;
    }
    let mut out: Vec<ProjectContentSummary> = summaries.into_values().collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
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
