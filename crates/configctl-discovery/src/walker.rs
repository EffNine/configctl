//! Bounded, deterministic filesystem traversal.
//!
//! Symlinks are never followed. The hard deny-list is applied before any
//! user rule, and every limit (depth, file count, byte count) is enforced
//! during the walk. Traversal is iterative (explicit stack) so deep trees
//! cannot overflow the call stack.

use configctl_core::governor::{GovernorDecision, ResourceGovernor};
use configctl_core::limits::Limits;

/// Outcome of a single walk.
#[derive(Debug, Default, Clone, serde::Serialize)]
#[serde(default)]
pub struct WalkStats {
    pub files: usize,
    pub directories: usize,
    pub permission_denied: usize,
    pub excluded: usize,
    pub depth_reached: usize,
    pub stop_reason: Option<StopReason>,
    /// Governor budget that stopped the walk, if any (e.g. `file_budget`).
    pub governor_limit: Option<String>,
}

impl WalkStats {
    /// True when the walk hit any limit or permission boundary.
    pub fn hit_any_bound(&self) -> bool {
        self.stop_reason.is_some() || self.permission_denied > 0
    }
}

/// Why the walk stopped early (if it did).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    DepthLimit,
    FileCountLimit,
    ByteLimit,
    FindingLimit,
    /// A central governor budget stopped traversal (see
    /// [`WalkStats::governor_limit`] for which one).
    GovernorLimit,
}

impl StopReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            StopReason::DepthLimit => "depth_limit",
            StopReason::FileCountLimit => "file_count_limit",
            StopReason::ByteLimit => "byte_limit",
            StopReason::FindingLimit => "finding_limit",
            StopReason::GovernorLimit => "governor_limit",
        }
    }
}

/// Directory/file names that must never be entered.
pub const HARD_DENY_DIRS: &[&str] = &[
    "proc",
    "sys",
    "dev",
    "run",
    "tmp",
    ".cache",
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
];

/// A single visited file entry.
pub struct Visit {
    pub path: std::path::PathBuf,
    pub depth: usize,
}

/// Traversal rules applied on top of the hard deny-list.
#[derive(Debug, Clone, Default)]
pub struct WalkRules {
    /// Exclude when the directory name matches any of these.
    pub exclude_dirs: Vec<String>,
}

impl WalkRules {
    /// Should this directory (by name) be pruned?
    pub fn is_excluded(&self, entry: &std::path::Path, stats: &mut WalkStats) -> bool {
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if HARD_DENY_DIRS.iter().any(|d| *d == name) {
            stats.excluded += 1;
            return true;
        }
        for ex in &self.exclude_dirs {
            if name == ex.as_str() {
                stats.excluded += 1;
                return true;
            }
        }
        false
    }
}

/// A bounded, iterative walker. Symlinks are never followed.
pub struct BoundedWalker {
    rules: WalkRules,
    limits: Limits,
    governor: Option<std::sync::Arc<ResourceGovernor>>,
}

impl BoundedWalker {
    pub fn new(limits: Limits) -> Self {
        Self {
            rules: WalkRules::default(),
            limits,
            governor: None,
        }
    }

    /// Attach the central resource governor. Budgets are enforced live
    /// during the walk; exhaustion records `governor_limit` explicitly.
    pub fn with_governor(mut self, governor: std::sync::Arc<ResourceGovernor>) -> Self {
        self.governor = Some(governor);
        self
    }

    pub fn with_rules(mut self, rules: WalkRules) -> Self {
        self.rules = rules;
        self
    }

    /// Walk `root` bounded by the configured limits, invoking `f` for each
    /// visited file. Returning `false` from `f` stops the walk early.
    pub fn walk(&self, root: &std::path::Path, f: &mut dyn FnMut(&Visit) -> bool) -> WalkStats {
        let mut stats = WalkStats::default();

        let root_children = match std::fs::read_dir(root) {
            Ok(iter) => iter.filter_map(|c| c.ok()).collect::<Vec<_>>(),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                stats.permission_denied += 1;
                return stats;
            }
            Err(_) => return stats,
        };

        let mut stack: Vec<(std::path::PathBuf, usize)> =
            root_children.iter().map(|c| (c.path(), 1usize)).collect();

        let mut files: usize = 0;
        let mut total_bytes: usize = 0;

        // Iterative DFS: pop (path, depth).
        while let Some((path, depth)) = stack.pop() {
            if depth > stats.depth_reached {
                stats.depth_reached = depth;
            }
            if depth > self.limits.max_depth {
                stats.stop_reason = Some(StopReason::DepthLimit);
                break;
            }
            // Governor: wall-clock check every iteration (cheap).
            if let Some(gov) = &self.governor {
                if gov.deadline_exceeded() {
                    stats.stop_reason = Some(StopReason::GovernorLimit);
                    stats.governor_limit = Some("wall_clock_budget".to_string());
                    break;
                }
                if gov.limit_hit().is_some() {
                    stats.stop_reason = Some(StopReason::GovernorLimit);
                    stats.governor_limit = gov.limit_hit().map(|s| s.to_string());
                    break;
                }
            }

            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    stats.permission_denied += 1;
                    continue;
                }
                Err(_) => continue,
            };

            // Symlinks: record as excluded, never read the target.
            if meta.file_type().is_symlink() {
                stats.excluded += 1;
                continue;
            }

            if meta.file_type().is_dir() {
                if self.rules.is_excluded(&path, &mut stats) {
                    continue;
                }
                stats.directories += 1;
                match std::fs::read_dir(&path) {
                    Ok(iter) => {
                        let children: Vec<_> = iter.filter_map(|c| c.ok()).collect();
                        if let Some(gov) = &self.governor {
                            match gov.account_dir_entries(children.len() as u64) {
                                GovernorDecision::Proceed => {}
                                GovernorDecision::LimitReached { reason } => {
                                    stats.stop_reason = Some(StopReason::GovernorLimit);
                                    stats.governor_limit = Some(reason.to_string());
                                    break;
                                }
                            }
                        }
                        for child in children {
                            stack.push((child.path(), depth + 1));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        stats.permission_denied += 1;
                    }
                    Err(_) => {}
                }
                continue;
            }

            if !meta.file_type().is_file() {
                stats.excluded += 1;
                continue;
            }

            files += 1;
            if files > self.limits.max_files_per_root {
                stats.stop_reason = Some(StopReason::FileCountLimit);
                break;
            }

            let size = meta.len() as usize;
            total_bytes += size;
            if total_bytes > self.limits.max_total_bytes {
                stats.stop_reason = Some(StopReason::ByteLimit);
                break;
            }

            // Governor: global file + byte budgets.
            if let Some(gov) = &self.governor {
                match gov.account_file(size as u64) {
                    GovernorDecision::Proceed => {}
                    GovernorDecision::LimitReached { reason } => {
                        stats.stop_reason = Some(StopReason::GovernorLimit);
                        stats.governor_limit = Some(reason.to_string());
                        break;
                    }
                }
            }

            let visit = Visit {
                path: path.clone(),
                depth,
            };
            if !f(&visit) {
                stats.stop_reason = Some(StopReason::FindingLimit);
                break;
            }
            stats.files += 1;
        }

        stats
    }
}
