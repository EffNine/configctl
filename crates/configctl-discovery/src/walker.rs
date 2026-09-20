//! Bounded, deterministic filesystem traversal.
//!
//! Symlinks are never followed. The hard deny-list is applied before any
//! user rule, and every limit (depth, file count, byte count) is enforced
//! during the walk. Traversal is iterative (explicit stack) so deep trees
//! cannot overflow the call stack.

use configctl_core::classify::FileKind;
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
    /// Breakdown of exclusions (recorded, never silent).
    pub symlinks_seen: u64,
    pub special_seen: u64,
    pub denied_prunes: u64,
    pub mount_boundaries: u64,
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
///
/// Regular files, symlinks, and special files are all yielded to the
/// callback (with their [`FileKind`]); directories are traversed, never
/// yielded. Symlinks are never followed.
pub struct Visit {
    pub path: std::path::PathBuf,
    pub depth: usize,
    pub kind: FileKind,
    /// File size for regular files (0 otherwise).
    pub size: u64,
    /// Owner-executable bit observed (regular files only).
    pub executable: bool,
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

        // Device boundary baseline for mount-aware scanning (0 = unknown).
        let root_dev = std::fs::symlink_metadata(root)
            .ok()
            .map(|m| meta_dev(&m))
            .unwrap_or(0);
        let stay_on_fs = self
            .governor
            .as_ref()
            .map(|g| g.budgets().stay_on_filesystem && !g.budgets().follow_mounts)
            .unwrap_or(true);

        let mut stack: Vec<(std::path::PathBuf, usize)> =
            root_children.iter().map(|c| (c.path(), 1usize)).collect();

        let mut files: usize = 0;
        let mut total_bytes: usize = 0;

        // Yield one non-directory visit to the callback. Honors `false` by
        // stopping with `FindingLimit`.
        macro_rules! yield_visit {
            ($stats:expr, $path:expr, $depth:expr, $kind:expr, $size:expr, $exec:expr) => {{
                let visit = Visit {
                    path: $path.clone(),
                    depth: $depth,
                    kind: $kind,
                    size: $size,
                    executable: $exec,
                };
                if !f(&visit) {
                    $stats.stop_reason = Some(StopReason::FindingLimit);
                    return $stats;
                }
            }};
        }

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

            let (mode, executable, dev) = meta_details(&meta);
            let kind = FileKind::from_file_type(&meta.file_type(), mode);

            // Symlinks: yielded for mapping, never followed.
            if kind == FileKind::Symlink {
                stats.excluded += 1;
                stats.symlinks_seen += 1;
                yield_visit!(stats, path, depth, kind, 0, false);
                continue;
            }

            if meta.file_type().is_dir() {
                // Mount boundary: record instead of descending blindly.
                if stay_on_fs && root_dev != 0 && dev != 0 && dev != root_dev {
                    stats.excluded += 1;
                    stats.mount_boundaries += 1;
                    continue;
                }
                if self.rules.is_excluded(&path, &mut stats) {
                    stats.denied_prunes += 1;
                    continue;
                }
                stats.directories += 1;
                // Yield directories for marker mapping (dir markers like
                // `.git`/`.github`); traversal still descends below.
                yield_visit!(stats, path, depth, FileKind::Directory, 0, false);
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

            // Special files: yielded for mapping, never opened.
            if kind.is_special() || kind == FileKind::Unknown {
                stats.excluded += 1;
                stats.special_seen += 1;
                yield_visit!(stats, path, depth, kind, 0, false);
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
                kind: FileKind::Regular,
                size: size as u64,
                executable,
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

/// Platform details for metadata: (mode, executable, device).
#[cfg(unix)]
fn meta_details(meta: &std::fs::Metadata) -> (Option<u32>, bool, u64) {
    use std::os::unix::fs::MetadataExt;
    let mode = meta.mode();
    (Some(mode), mode & 0o111 != 0, meta.dev())
}

/// Platform details for metadata: (mode, executable, device).
#[cfg(not(unix))]
fn meta_details(_meta: &std::fs::Metadata) -> (Option<u32>, bool, u64) {
    (None, false, 0)
}

/// Device id for mount-boundary detection (0 = unknown).
#[cfg(unix)]
fn meta_dev(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.dev()
}

/// Device id for mount-boundary detection (0 = unknown).
#[cfg(not(unix))]
fn meta_dev(_meta: &std::fs::Metadata) -> u64 {
    0
}
