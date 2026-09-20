//! v1.1 central resource governor.
//!
//! Hardcore discovery with bounded execution: every discovery subsystem
//! consumes budgets from a single [`ResourceGovernor`]. The governor tracks
//! wall-clock time, files visited, bytes read, subprocesses spawned, output
//! captured, recursion/symlink depth, and memory estimates. When any budget
//! is exhausted the subsystem stops that work, records `LIMIT_REACHED`
//! (never a silent omission), and the scan finishes `PARTIAL`.
//!
//! Defaults target large developer machines without endangering them.
//! Explicit overrides are always passed through [`GovernorBudgets::sanitize`]
//! so even user-supplied values have hard sanity ceilings.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// v1.1 discovery budgets. All limits are enforced; none may be unlimited.
#[derive(Debug, Clone)]
pub struct GovernorBudgets {
    /// Total wall-clock time for the whole scan.
    pub max_wall_time: Duration,
    /// Worker pool size.
    pub max_workers: usize,
    /// Total files visited across all roots.
    pub max_file_count: u64,
    /// Total directory entries read across all roots.
    pub max_directory_entries: u64,
    /// Total bytes read from file content across the whole scan.
    pub max_total_bytes_read: u64,
    /// Largest single file ever read fully.
    pub max_single_file_read: u64,
    /// Maximum traversal recursion depth.
    pub max_recursion_depth: usize,
    /// Maximum symlink chain depth followed for classification.
    pub max_symlink_depth: usize,
    /// Maximum subprocesses spawned during the whole scan.
    pub max_subprocesses: u32,
    /// Timeout for any single subprocess.
    pub max_subprocess_runtime: Duration,
    /// Stdout+stderr cap for any single subprocess.
    pub max_subprocess_output: usize,
    /// Soft cap for scan-held buffers (streaming preferred past this).
    pub max_memory_bytes: u64,
    /// Never cross a filesystem boundary detected via mount table.
    pub stay_on_filesystem: bool,
    /// Reserved: allow crossing into other local mounts (default false).
    pub follow_mounts: bool,
    /// Reserved: allow recursive scans of network mounts (default false).
    pub scan_network_mounts: bool,
}

impl Default for GovernorBudgets {
    fn default() -> Self {
        Self {
            max_wall_time: Duration::from_secs(10 * 60),
            max_workers: default_workers(),
            max_file_count: 5_000_000,
            max_directory_entries: 10_000_000,
            max_total_bytes_read: 20 * 1024 * 1024 * 1024,
            max_single_file_read: 256 * 1024 * 1024,
            max_recursion_depth: 64,
            max_symlink_depth: 16,
            max_subprocesses: 64,
            max_subprocess_runtime: Duration::from_secs(10),
            max_subprocess_output: 1024 * 1024,
            max_memory_bytes: 2 * 1024 * 1024 * 1024,
            stay_on_filesystem: true,
            follow_mounts: false,
            scan_network_mounts: false,
        }
    }
}

/// Conservative worker default: `min(8, parallelism)`, at least 1.
pub fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().min(8).max(1))
        .unwrap_or(4)
}

impl GovernorBudgets {
    /// Clamp every budget to its hard sanity ceiling. Even explicit user
    /// overrides cannot request dangerous values.
    pub fn sanitize(mut self) -> Self {
        self.max_wall_time = self.max_wall_time.min(Duration::from_secs(120 * 60));
        if self.max_wall_time < Duration::from_secs(1) {
            self.max_wall_time = Duration::from_secs(1);
        }
        self.max_workers = self.max_workers.clamp(1, 32);
        self.max_file_count = self.max_file_count.clamp(1, 50_000_000);
        self.max_directory_entries = self.max_directory_entries.clamp(1, 100_000_000);
        self.max_total_bytes_read = self
            .max_total_bytes_read
            .clamp(1024 * 1024, 1024 * 1024 * 1024 * 1024);
        self.max_single_file_read = self
            .max_single_file_read
            .clamp(4096, 1024 * 1024 * 1024);
        self.max_recursion_depth = self.max_recursion_depth.clamp(1, 256);
        self.max_symlink_depth = self.max_symlink_depth.clamp(1, 64);
        self.max_subprocesses = self.max_subprocesses.clamp(1, 512);
        self.max_subprocess_runtime = self
            .max_subprocess_runtime
            .clamp(Duration::from_secs(1), Duration::from_secs(120));
        self.max_subprocess_output = self
            .max_subprocess_output
            .clamp(4096, 64 * 1024 * 1024);
        self.max_memory_bytes = self
            .max_memory_bytes
            .clamp(64 * 1024 * 1024, 32 * 1024 * 1024 * 1024);
        self
    }

    /// Bridge from the v1 [`crate::limits::Limits`] model.
    pub fn from_limits(limits: &crate::limits::Limits) -> Self {
        let mut b = Self::default();
        b.max_recursion_depth = limits.max_depth.min(256).max(1);
        b.max_file_count = (limits.max_files_total as u64).clamp(1, 50_000_000);
        b.max_total_bytes_read = (limits.max_total_bytes as u64).clamp(1024 * 1024, 1024 * 1024 * 1024 * 1024);
        b.max_single_file_read = (limits.max_file_bytes as u64).clamp(4096, 1024 * 1024 * 1024);
        b.max_subprocess_output = limits.subprocess_output_cap.clamp(4096, 64 * 1024 * 1024);
        b.max_subprocess_runtime = limits
            .subprocess_timeout
            .clamp(Duration::from_secs(1), Duration::from_secs(120));
        b
    }
}

/// Parse a human duration: `500ms`, `30s`, `20m`, `2h`, or bare seconds.
pub fn parse_duration(raw: &str) -> Result<Duration, String> {
    let s = raw.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        return ms
            .trim()
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|_| format!("invalid duration {raw:?}"));
    }
    if let Some(sec) = s.strip_suffix('s') {
        return sec
            .trim()
            .parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|_| format!("invalid duration {raw:?}"));
    }
    if let Some(min) = s.strip_suffix('m') {
        return min
            .trim()
            .parse::<u64>()
            .map(|m| Duration::from_secs(m * 60))
            .map_err(|_| format!("invalid duration {raw:?}"));
    }
    if let Some(h) = s.strip_suffix('h') {
        return h
            .trim()
            .parse::<u64>()
            .map(|h| Duration::from_secs(h * 3600))
            .map_err(|_| format!("invalid duration {raw:?}"));
    }
    s.parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| format!("invalid duration {raw:?} (try `20m`, `90s`, `2h`)"))
}

/// Parse a human byte count: `100GiB`, `20G`, `512MiB`, `1M`, `256KiB`,
/// `4096`, or bare bytes.
pub fn parse_bytes(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    // Longest suffixes first so `100gb` matches `gb`, not `b`.
    let units: &[(&str, u64)] = &[
        ("gib", 1024 * 1024 * 1024),
        ("mib", 1024 * 1024),
        ("kib", 1024),
        ("gb", 1000 * 1000 * 1000),
        ("mb", 1000 * 1000),
        ("kb", 1000),
        ("g", 1024 * 1024 * 1024),
        ("m", 1024 * 1024),
        ("k", 1024),
        ("b", 1),
    ];
    let lower = s.to_lowercase();
    for (suffix, mult) in units {
        if let Some(num) = lower.strip_suffix(suffix) {
            let num = num.trim();
            if num.is_empty() {
                continue;
            }
            return num
                .parse::<f64>()
                .map(|v| (v * *mult as f64) as u64)
                .map_err(|_| format!("invalid byte count {raw:?}"));
        }
    }
    s.parse::<u64>()
        .map_err(|_| format!("invalid byte count {raw:?} (try `100GiB`, `512MiB`)"))
}

/// Budget check outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernorDecision {
    Proceed,
    LimitReached { reason: &'static str },
}

/// System pressure level (advisory; the governor yields workers under load).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pressure {
    Normal,
    High,
    Critical,
}

/// Shared, thread-safe governor state.
#[derive(Debug)]
pub struct ResourceGovernor {
    budgets: GovernorBudgets,
    start: Instant,
    files: AtomicU64,
    dir_entries: AtomicU64,
    bytes_read: AtomicU64,
    subprocesses_total: AtomicU64,
    subprocesses_live: AtomicU64,
    limit_hit: Mutex<Option<&'static str>>,
    disabled: AtomicBool,
}

impl ResourceGovernor {
    pub fn new(budgets: GovernorBudgets) -> Arc<Self> {
        Arc::new(Self {
            budgets: budgets.sanitize(),
            start: Instant::now(),
            files: AtomicU64::new(0),
            dir_entries: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            subprocesses_total: AtomicU64::new(0),
            subprocesses_live: AtomicU64::new(0),
            limit_hit: Mutex::new(None),
            disabled: AtomicBool::new(false),
        })
    }

    pub fn budgets(&self) -> &GovernorBudgets {
        &self.budgets
    }

    /// Elapsed wall-clock time since governor creation.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// True when the wall-clock budget is exhausted (records the limit).
    pub fn deadline_exceeded(&self) -> bool {
        if self.start.elapsed() >= self.budgets.max_wall_time {
            self.note_limit("wall_clock_budget");
            true
        } else {
            false
        }
    }

    /// Account one visited file (+ its content bytes read, if any).
    pub fn account_file(&self, content_bytes: u64) -> GovernorDecision {
        let files = self.files.fetch_add(1, Ordering::Relaxed) + 1;
        if files > self.budgets.max_file_count {
            self.note_limit("file_budget");
            return GovernorDecision::LimitReached {
                reason: "file_budget",
            };
        }
        if content_bytes > 0 {
            let total = self.bytes_read.fetch_add(content_bytes, Ordering::Relaxed) + content_bytes;
            if total > self.budgets.max_total_bytes_read {
                self.note_limit("io_budget");
                return GovernorDecision::LimitReached { reason: "io_budget" };
            }
        }
        if self.deadline_exceeded() {
            return GovernorDecision::LimitReached {
                reason: "wall_clock_budget",
            };
        }
        GovernorDecision::Proceed
    }

    /// Account directory entries read from a single `read_dir`.
    pub fn account_dir_entries(&self, count: u64) -> GovernorDecision {
        let total = self.dir_entries.fetch_add(count, Ordering::Relaxed) + count;
        if total > self.budgets.max_directory_entries {
            self.note_limit("directory_entry_budget");
            return GovernorDecision::LimitReached {
                reason: "directory_entry_budget",
            };
        }
        GovernorDecision::Proceed
    }

    /// Whether a file of `size` may be read fully.
    pub fn may_read_file(&self, size: u64) -> GovernorDecision {
        if size > self.budgets.max_single_file_read {
            return GovernorDecision::LimitReached {
                reason: "single_file_budget",
            };
        }
        let projected = self.bytes_read.load(Ordering::Relaxed) + size;
        if projected > self.budgets.max_total_bytes_read {
            self.note_limit("io_budget");
            return GovernorDecision::LimitReached { reason: "io_budget" };
        }
        GovernorDecision::Proceed
    }

    /// Acquire a subprocess slot. Returns a guard that releases the live
    /// slot on drop; `None` when the subprocess budget is exhausted.
    pub fn acquire_subprocess(self: &Arc<Self>) -> Option<SubprocessGuard> {
        let total = self.subprocesses_total.fetch_add(1, Ordering::Relaxed) + 1;
        if total > self.budgets.max_subprocesses as u64 {
            self.note_limit("subprocess_budget");
            return None;
        }
        self.subprocesses_live.fetch_add(1, Ordering::Relaxed);
        Some(SubprocessGuard {
            governor: Arc::clone(self),
        })
    }

    /// Build a governor-bounded [`crate::command::CommandRequest`].
    pub fn subprocess_request(
        &self,
        program: impl Into<std::path::PathBuf>,
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> crate::command::CommandRequest {
        crate::command::CommandRequest::new(program, args)
            .timeout(self.budgets.max_subprocess_runtime)
            .output_cap(self.budgets.max_subprocess_output)
    }

    fn note_limit(&self, reason: &'static str) {
        if let Ok(mut hit) = self.limit_hit.lock() {
            if hit.is_none() {
                *hit = Some(reason);
            }
        }
    }

    /// First exhausted budget, if any.
    pub fn limit_hit(&self) -> Option<&'static str> {
        let guard = self.limit_hit.lock().ok()?;
        (*guard).as_ref().copied()
    }

    /// Point-in-time snapshot for reports.
    pub fn snapshot(&self) -> GovernorSnapshot {
        GovernorSnapshot {
            elapsed_secs: self.start.elapsed().as_secs(),
            files: self.files.load(Ordering::Relaxed),
            dir_entries: self.dir_entries.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            subprocesses_total: self.subprocesses_total.load(Ordering::Relaxed),
            limit_hit: self.limit_hit().map(|s| s.to_string()),
            cpu_pressure: format!("{:?}", cpu_pressure().to_lower()),
            memory_pressure: format!("{:?}", memory_pressure().to_lower()),
        }
    }

    /// Worker count adapted to current CPU pressure.
    pub fn suggested_workers(&self) -> usize {
        let base = self.budgets.max_workers.max(1);
        match cpu_pressure() {
            Pressure::Normal => base,
            Pressure::High => (base / 2).max(1),
            Pressure::Critical => 1,
        }
    }
}

/// RAII live-subprocess slot; releases on drop.
#[derive(Debug)]
pub struct SubprocessGuard {
    governor: Arc<ResourceGovernor>,
}

impl Drop for SubprocessGuard {
    fn drop(&mut self) {
        self.governor
            .subprocesses_live
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// Serializable governor state for scan reports.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GovernorSnapshot {
    pub elapsed_secs: u64,
    pub files: u64,
    pub dir_entries: u64,
    pub bytes_read: u64,
    pub subprocesses_total: u64,
    pub limit_hit: Option<String>,
    pub cpu_pressure: String,
    pub memory_pressure: String,
}

/// Current CPU pressure from `/proc/loadavg` vs parallelism.
pub fn cpu_pressure() -> Pressure {
    let ncpu = std::thread::available_parallelism()
        .map(|n| n.get() as f64)
        .unwrap_or(1.0)
        .max(1.0);
    let load = read_loadavg_1m().unwrap_or(0.0);
    if load >= ncpu * 2.0 {
        Pressure::Critical
    } else if load >= ncpu {
        Pressure::High
    } else {
        Pressure::Normal
    }
}

fn read_loadavg_1m() -> Option<f64> {
    let text = std::fs::read_to_string("/proc/loadavg").ok()?;
    text.split_whitespace().next()?.parse::<f64>().ok()
}

impl Pressure {
    fn to_lower(self) -> &'static str {
        match self {
            Pressure::Normal => "normal",
            Pressure::High => "high",
            Pressure::Critical => "critical",
        }
    }
}

/// Current memory pressure from `/proc/meminfo` (MemAvailable/MemTotal).
pub fn memory_pressure() -> Pressure {
    let (total, avail) = read_meminfo().unwrap_or((1, 1));
    if total == 0 {
        return Pressure::Normal;
    }
    let used_frac = 1.0 - (avail as f64 / total as f64);
    if used_frac >= 0.95 {
        Pressure::Critical
    } else if used_frac >= 0.85 {
        Pressure::High
    } else {
        Pressure::Normal
    }
}

fn read_meminfo() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = None;
    let mut avail = None;
    for line in text.lines() {
        if line.starts_with("MemTotal:") {
            total = line.split_whitespace().nth(1)?.parse::<u64>().ok();
        } else if line.starts_with("MemAvailable:") {
            avail = line.split_whitespace().nth(1)?.parse::<u64>().ok();
        }
    }
    Some((total?, avail?))
}

#[cfg(test)]
mod governor_tests {
    use super::*;

    #[test]
    fn sanitize_enforces_hard_ceilings() {
        let b = GovernorBudgets {
            max_wall_time: Duration::from_secs(1_000_000),
            max_workers: 10_000,
            max_file_count: u64::MAX,
            max_subprocesses: u32::MAX,
            max_subprocess_output: usize::MAX,
            ..GovernorBudgets::default()
        }
        .sanitize();
        assert!(b.max_wall_time <= Duration::from_secs(120 * 60));
        assert!(b.max_workers <= 32);
        assert!(b.max_file_count <= 50_000_000);
        assert!(b.max_subprocesses <= 512);
        assert!(b.max_subprocess_output <= 64 * 1024 * 1024);
    }

    #[test]
    fn file_budget_exhaustion_is_explicit() {
        let gov = ResourceGovernor::new(GovernorBudgets {
            max_file_count: 2,
            ..GovernorBudgets::default()
        });
        assert_eq!(gov.account_file(0), GovernorDecision::Proceed);
        assert_eq!(gov.account_file(0), GovernorDecision::Proceed);
        assert_eq!(
            gov.account_file(0),
            GovernorDecision::LimitReached { reason: "file_budget" }
        );
        assert_eq!(gov.limit_hit(), Some("file_budget"));
    }

    #[test]
    fn subprocess_slots_are_bounded_and_released() {
        let gov = ResourceGovernor::new(GovernorBudgets {
            max_subprocesses: 1,
            ..GovernorBudgets::default()
        });
        let g1 = gov.acquire_subprocess();
        assert!(g1.is_some());
        assert!(gov.acquire_subprocess().is_none());
        drop(g1);
        // Total budget counts spawns, not live slots: still exhausted.
        assert!(gov.acquire_subprocess().is_none());
        assert_eq!(gov.limit_hit(), Some("subprocess_budget"));
    }

    #[test]
    fn parse_durations_and_bytes() {
        assert_eq!(parse_duration("20m").unwrap(), Duration::from_secs(1200));
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_bytes("100GiB").unwrap(), 100 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("512MiB").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_bytes("20G").unwrap(), 20 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("4096").unwrap(), 4096);
        assert!(parse_duration("soon").is_err());
        assert!(parse_bytes("lots").is_err());
    }
}
