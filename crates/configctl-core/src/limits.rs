//! Global resource limits for bounded discovery.
//!
//! v1.1: defaults are scaled to match the central [`crate::governor`]
//! budgets so legacy per-root caps are not the premature bottleneck on
//! large developer machines. The governor remains the binding authority
//! (whole-scan budgets, wall time, subprocesses); these caps bound
//! individual roots and single-file content parsing.

/// Discovery limits for a single scan.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Maximum recursion depth below a scan root.
    pub max_depth: usize,
    /// Maximum number of files visited per root.
    pub max_files_per_root: usize,
    /// Maximum total files visited across all roots.
    pub max_files_total: usize,
    /// Maximum bytes inspected per file.
    pub max_file_bytes: usize,
    /// Maximum total bytes inspected across the whole scan.
    pub max_total_bytes: usize,
    /// Maximum number of findings retained.
    pub max_findings: usize,
    /// Subprocess output cap (bytes).
    pub subprocess_output_cap: usize,
    /// Subprocess timeout.
    pub subprocess_timeout: std::time::Duration,
}

impl Default for Limits {
    fn default() -> Self {
        // 20 GiB saturates gracefully on 32-bit targets.
        let twenty_gib = (20u64 * 1024 * 1024 * 1024).min(usize::MAX as u64) as usize;
        Self {
            max_depth: 64,
            max_files_per_root: 1_000_000,
            max_files_total: 5_000_000,
            max_file_bytes: 256 * 1024,
            max_total_bytes: twenty_gib,
            max_findings: 10_000,
            subprocess_output_cap: 256 * 1024,
            subprocess_timeout: std::time::Duration::from_secs(30),
        }
    }
}
