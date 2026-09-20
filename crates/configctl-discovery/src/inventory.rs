//! v1.1 inventory collector: observe → classify → count.
//!
//! Pure collection layer over filesystem visits. Symlink targets are resolved
//! with a bounded chain walk (cycle detection, max depth 16); nothing is
//! ever followed outside the recorded relationship.

use configctl_core::classify::{FileKind, classify_file};
use configctl_core::inventory::{CompletenessReport, FilesystemEntry, InventoryCounters, SymlinkRecord};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// Maximum symlink chain depth followed for classification.
pub const MAX_SYMLINK_DEPTH: usize = 16;

/// Maximum symlink relationships retained (overflow counted explicitly).
pub const MAX_SYMLINKS: usize = 5000;

/// Bounded inventory collector.
#[derive(Debug, Default)]
pub struct InventoryCollector {
    counters: InventoryCounters,
    class_counts: BTreeMap<String, u64>,
    symlinks: Vec<SymlinkRecord>,
    symlinks_truncated: bool,
    symlinks_overflow: u64,
    completeness: CompletenessReport,
    scan_root: Option<PathBuf>,
}

impl InventoryCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Scope symlink inside/outside classification to a scan root.
    pub fn set_scan_root(&mut self, root: PathBuf) {
        self.scan_root = Some(root);
    }

    /// Observe one path with already-stat'ed metadata (no I/O here except
    /// `read_link` for symlinks, which never touches the target).
    pub fn observe(&mut self, path: &Path, file_type: &std::fs::FileType, mode: Option<u32>) {
        let kind = FileKind::from_file_type(file_type, mode);
        #[cfg(unix)]
        let executable = mode.map(|m| m & 0o111 != 0).unwrap_or(false);
        #[cfg(not(unix))]
        let executable = false;
        let size = if kind == FileKind::Regular {
            std::fs::symlink_metadata(path).ok().map(|m| m.len())
        } else {
            None
        };
        self.observe_typed(path, kind, size, executable);
    }

    /// Observe one visit with walker-supplied type/size/exec (no extra I/O
    /// except `read_link` for symlinks).
    pub fn observe_typed(
        &mut self,
        path: &Path,
        kind: FileKind,
        size: Option<u64>,
        executable: bool,
    ) -> Option<FilesystemEntry> {
        match kind {
            FileKind::Directory => self.counters.directories += 1,
            FileKind::Symlink => {
                self.counters.symlinks += 1;
                let root = self.scan_root.clone();
                self.record_symlink(path, root.as_deref());
                self.completeness.observed += 1;
                self.completeness.mapped += 1;
                return None;
            }
            FileKind::Socket => self.counters.sockets += 1,
            FileKind::Fifo => self.counters.fifos += 1,
            FileKind::BlockDevice | FileKind::CharDevice => self.counters.devices += 1,
            FileKind::Unknown => self.counters.unknown_types += 1,
            FileKind::Regular => {
                self.counters.files += 1;
                if executable {
                    self.counters.executables += 1;
                }
            }
        }
        self.completeness.observed += 1;
        self.completeness.mapped += 1;
        if kind != FileKind::Regular {
            // Special files: counted + recorded, never opened or parsed.
            // Aggregate skip reasons come from walk stats (real counts).
            return None;
        }
        let c = classify_file(path, FileKind::Regular, executable);
        *self
            .class_counts
            .entry(c.class.as_str().to_string())
            .or_insert(0) += 1;
        Some(FilesystemEntry::from_classification(
            path.to_string_lossy().into_owned(),
            FileKind::Regular,
            size,
            executable,
            c,
        ))
    }

    /// Observe a regular file with classification evidence.
    pub fn observe_file(&mut self, path: &Path, size: Option<u64>, executable: bool) -> FilesystemEntry {
        self.counters.files += 1;
        if executable {
            self.counters.executables += 1;
        }
        let c = classify_file(path, FileKind::Regular, executable);
        *self
            .class_counts
            .entry(c.class.as_str().to_string())
            .or_insert(0) += 1;
        self.completeness.observed += 1;
        self.completeness.mapped += 1;
        FilesystemEntry::from_classification(
            path.to_string_lossy().into_owned(),
            FileKind::Regular,
            size,
            executable,
            c,
        )
    }

    /// Record a skipped resource with an explicit reason (never silent).
    pub fn record_skip(&mut self, reason: &str, count: u64) {
        self.completeness.record_skip(reason, count);
    }

    fn record_symlink(&mut self, path: &Path, scan_root: Option<&Path>) {
        let raw = std::fs::read_link(path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let is_relative = Path::new(&raw).is_relative();
        let resolved = resolve_chain(path, MAX_SYMLINK_DEPTH);
        let inside_root = match (&resolved.target, scan_root) {
            (Some(t), Some(root)) => Some(t.starts_with(root)),
            _ => None,
        };
        if self.symlinks.len() >= MAX_SYMLINKS {
            self.symlinks_truncated = true;
            self.symlinks_overflow += 1;
            return;
        }
        self.symlinks.push(SymlinkRecord {
            path: path.to_string_lossy().into_owned(),
            target: raw,
            target_exists: resolved.exists,
            is_relative,
            inside_root,
            target_class: None,
            depth: resolved.depth,
            cycle: if resolved.cycle { Some(true) } else { None },
        });
    }

    pub fn counters(&self) -> &InventoryCounters {
        &self.counters
    }

    pub fn class_counts(&self) -> &BTreeMap<String, u64> {
        &self.class_counts
    }

    pub fn symlinks(&self) -> &[SymlinkRecord] {
        &self.symlinks
    }

    pub fn symlinks_truncated(&self) -> bool {
        self.symlinks_truncated
    }

    pub fn symlinks_overflow(&self) -> u64 {
        self.symlinks_overflow
    }

    pub fn completeness(&self) -> &CompletenessReport {
        &self.completeness
    }
}

struct ChainResolution {
    target: Option<PathBuf>,
    exists: bool,
    depth: usize,
    cycle: bool,
}

/// Follow a symlink chain without ever opening the target: only `read_link`
/// + `symlink_metadata` (lstat-equivalent), bounded by `max_depth`, with
/// cycle detection over visited paths.
fn resolve_chain(start: &Path, max_depth: usize) -> ChainResolution {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut current = start.to_path_buf();
    let mut depth = 0usize;
    seen.insert(current.clone());
    loop {
        if depth >= max_depth {
            let exists = current.symlink_metadata().is_ok();
            return ChainResolution {
                target: Some(current),
                exists,
                depth,
                cycle: false,
            };
        }
        let next = match std::fs::read_link(&current) {
            Ok(t) => {
                if t.is_absolute() {
                    t
                } else {
                    match current.parent() {
                        Some(p) => p.join(t),
                        None => {
                            return ChainResolution {
                                target: None,
                                exists: false,
                                depth,
                                cycle: false,
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // `current` is not a symlink: terminal target.
                return ChainResolution {
                    target: Some(current.clone()),
                    exists: current.symlink_metadata().is_ok(),
                    depth,
                    cycle: false,
                };
            }
        };
        depth += 1;
        if !seen.insert(next.clone()) {
            return ChainResolution {
                target: Some(next),
                exists: false,
                depth,
                cycle: true,
            };
        }
        current = next;
    }
}
