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
pub mod env;
pub mod git;
pub mod inventory;
pub mod packages;
pub mod project;
pub mod scanner;
pub mod secret;
pub mod system;
pub mod toolchain;
pub mod walker;

pub use scanner::{ScanOptions, ScanResult, ScanStats, Scanner};
pub use system::SystemInfo;
pub use walker::WalkStats;
