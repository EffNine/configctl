//! v1.1 comprehensive resource inventory model.
//!
//! The inventory is the forensic layer between discovery and capture: every
//! observed resource is counted, classified, and given an explicit capture
//! decision. [`CompletenessReport`] makes partial scans observable instead of
//! silent.

use crate::classify::{CaptureAction, Classification, FileKind, ResourceClass};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One observed filesystem resource with its verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemEntry {
    /// Absolute path as observed.
    pub path: String,
    pub kind: FileKind,
    /// File size in bytes (regular files only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Owner-executable bit observed.
    #[serde(default)]
    pub executable: bool,
    pub classification: ResourceClass,
    pub action: CaptureAction,
    #[serde(default)]
    pub signals: Vec<String>,
    /// Required reason for the capture decision.
    pub reason: String,
}

impl FilesystemEntry {
    pub fn from_classification(
        path: String,
        kind: FileKind,
        size: Option<u64>,
        executable: bool,
        c: Classification,
    ) -> Self {
        Self {
            path,
            kind,
            size,
            executable,
            classification: c.class,
            action: c.action,
            signals: c.signals,
            reason: c.reason,
        }
    }
}

/// A mapped symlink relationship (target analysis, bounded at discovery).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymlinkRecord {
    pub path: String,
    /// Raw `read_link` target (may be relative).
    pub target: String,
    pub target_exists: bool,
    pub is_relative: bool,
    /// Whether the resolved target stays inside the scan root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inside_root: Option<bool>,
    /// Resolved target classification when established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_class: Option<ResourceClass>,
    /// Chain depth followed to classify (bounded; cycles stop at revisit).
    pub depth: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycle: Option<bool>,
}

/// Whole-scan resource counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InventoryCounters {
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub executables: u64,
    pub sockets: u64,
    pub fifos: u64,
    pub devices: u64,
    pub unknown_types: u64,
    pub projects: u64,
    pub packages: u64,
    pub services: u64,
    pub env_vars: u64,
    pub mounts: u64,
    pub credentials: u64,
}

impl InventoryCounters {
    /// Total resources observed across all counted dimensions.
    pub fn observed_total(&self) -> u64 {
        self.files
            + self.directories
            + self.symlinks
            + self.sockets
            + self.fifos
            + self.devices
            + self.unknown_types
    }
}

/// Scan terminal status. `Partial` always carries at least one reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ScanStatus {
    Complete,
    Partial,
}

/// Completeness report: observed vs mapped vs skipped with reasons.
///
/// Never report `Complete` when any governor budget stopped traversal early
/// or any skip bucket is non-zero for a reason other than policy exclusion.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CompletenessReport {
    pub observed: u64,
    pub mapped: u64,
    pub skipped: u64,
    /// `reason → count`, e.g. `permission_denied → 12`.
    pub reasons: BTreeMap<String, u64>,
    pub status: Option<ScanStatus>,
}

impl CompletenessReport {
    pub fn record_skip(&mut self, reason: &str, count: u64) {
        *self.reasons.entry(reason.to_string()).or_insert(0) += count;
        self.skipped += count;
    }

    /// Percentage of observed resources mapped (0–100).
    pub fn completeness_pct(&self) -> f64 {
        if self.observed == 0 {
            return 100.0;
        }
        (self.mapped as f64 / self.observed as f64 * 100.0).clamp(0.0, 100.0)
    }

    /// Finalize: `budget_exhausted` must be true when any governor budget
    /// stopped traversal early.
    pub fn finalize(&mut self, budget_exhausted: bool) {
        self.status = Some(if budget_exhausted || self.skipped > 0 {
            ScanStatus::Partial
        } else {
            ScanStatus::Complete
        });
    }

    /// Render the human-readable completeness block.
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str("SCAN COMPLETENESS\n");
        out.push_str(&format!("  observed: {}\n", self.observed));
        out.push_str(&format!("  mapped:   {}\n", self.mapped));
        out.push_str(&format!("  skipped:  {}\n", self.skipped));
        out.push_str("  reasons:\n");
        let mut reasons: Vec<(&String, &u64)> = self.reasons.iter().collect();
        reasons.sort_by(|a, b| b.1.cmp(a.1));
        if reasons.is_empty() {
            out.push_str("    (none)\n");
        }
        for (reason, count) in reasons {
            out.push_str(&format!("    {reason}: {count}\n"));
        }
        out.push_str(&format!(
            "  completeness: {:.2}%\n",
            self.completeness_pct()
        ));
        match self.status {
            Some(ScanStatus::Complete) => out.push_str("  status: COMPLETE\n"),
            Some(ScanStatus::Partial) => out.push_str("  status: PARTIAL\n"),
            None => out.push_str("  status: UNKNOWN (not finalized)\n"),
        }
        out
    }
}

#[cfg(test)]
mod model_tests {
    use super::*;

    #[test]
    fn completeness_partial_when_skips_exist() {
        let mut r = CompletenessReport {
            observed: 100,
            mapped: 90,
            ..Default::default()
        };
        r.record_skip("permission_denied", 10);
        r.finalize(false);
        assert_eq!(r.status, Some(ScanStatus::Partial));
        assert!((r.completeness_pct() - 90.0).abs() < 1e-9);
    }

    #[test]
    fn completeness_complete_when_nothing_skipped() {
        let mut r = CompletenessReport {
            observed: 10,
            mapped: 10,
            ..Default::default()
        };
        r.finalize(false);
        assert_eq!(r.status, Some(ScanStatus::Complete));
    }
}
