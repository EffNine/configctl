//! Global resource limits for bounded discovery.
//!
//! Every limit has a safe default; the CLI may override them through
//! configuration later. These caps are DoS protection, not an optimization
//! framework.

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
        Self {
            max_depth: 32,
            max_files_per_root: 20_000,
            max_files_total: 100_000,
            max_file_bytes: 256 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_findings: 10_000,
            subprocess_output_cap: 256 * 1024,
            subprocess_timeout: std::time::Duration::from_secs(30),
        }
    }
}
