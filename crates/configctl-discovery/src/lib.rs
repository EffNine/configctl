//! configctl-discovery: read-only discovery engine for `configctl scan`.
//!
//! Pipeline: SCAN → DISCOVER → CLASSIFY → REDACT → REPORT. No mutation.
//!
//! Modules:
//! - `walker` — bounded filesystem traversal
//! - `project` — project marker detection
//! - `env` — `.env` discovery, parsing, secret classification
//! - `config` — config-file discovery registry
//! - `git` — git tracking detection via `CommandRunner`
//! - `system` — machine/system metadata
//! - `scanner` — the scan service that composes everything

pub mod config;
pub mod credentials;
pub mod env;
pub mod environment;
pub mod filesystem;
pub mod git;
pub mod hardware;
pub mod inventory;
pub mod mounts;
pub mod packages;
pub mod project;
pub mod scanner;
pub mod secret;
pub mod services;
pub mod system;
pub mod toolchain;
pub mod walker;

pub use scanner::{ScanOptions, ScanResult, ScanStats, Scanner};
pub use system::SystemInfo;
pub use walker::WalkStats;

#[cfg(test)]
mod tests {
    use super::*;

    /// The crate's public re-export surface must stay constructible; a broken
    /// re-export is a compile error here rather than a downstream surprise.
    #[test]
    fn public_reexports_are_reachable() {
        let opts = ScanOptions::default();
        assert!(opts.roots.is_empty());
        let _stats = WalkStats::default();
        let info = SystemInfo::default();
        assert_eq!(info.os, "");
    }
}
