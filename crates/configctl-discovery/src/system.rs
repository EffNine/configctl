//! Machine/system metadata for contextualizing a scan.
//!
//! Read-only. Subprocess probes go through `CommandRunner`. Nothing is
//! installed and PATH is never modified.

use configctl_core::command::{CommandError, CommandRunner};
use configctl_core::governor::ResourceGovernor;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

/// Tool availability result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolAvailability {
    pub available: bool,
    pub version: Option<String>,
}

/// System metadata collected for a scan.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(default)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub distro: Option<String>,
    pub kernel: Option<String>,
    pub hostname: Option<String>,
    pub tools: BTreeSet<String>,
    pub details: std::collections::BTreeMap<String, ToolAvailability>,
}

impl SystemInfo {
    /// True when a tool is in `details` and available.
    pub fn has(&self, tool: &str) -> bool {
        self.details.get(tool).map(|t| t.available).unwrap_or(false)
    }
}

/// Collect system metadata. `cwd` is a scratch dir (used as subprocess cwd).
/// Tool probes run through the governor like every other subprocess.
pub fn collect(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
    cwd: &Path,
) -> SystemInfo {
    let mut info = SystemInfo {
        os: "linux".into(),
        arch: std::env::consts::ARCH.to_string(),
        ..SystemInfo::default()
    };
    info.distro = read_distro();
    info.kernel = read_kernel();
    info.hostname = read_hostname();

    // Tools
    let tools: Vec<(&str, Vec<&str>)> = vec![
        ("git", vec!["--version"]),
        ("cargo", vec!["--version"]),
        ("rustc", vec!["--version"]),
        ("python3", vec!["--version"]),
        ("node", vec!["--version"]),
        ("npm", vec!["--version"]),
        ("go", vec!["version"]),
        ("systemctl", vec!["--version"]),
        ("apt", vec!["--version"]),
        ("docker", vec!["--version"]),
    ];

    let mut found: BTreeSet<String> = BTreeSet::new();
    for (tool, version_args) in &tools {
        let mut req = governor.subprocess_request(*tool, version_args.iter().copied());
        req.cwd = Some(cwd.to_path_buf());
        req.output_cap = Some(4096);
        // Governor spawn slot first (fail-closed on budget exhaustion).
        let _slot = governor.acquire_subprocess();
        let out = match _slot {
            Some(_) => runner.run(&req),
            None => Err(CommandError::SpawnFailed),
        };
        match out {
            Ok(out) if out.status == Some(0) => {
                let version = out
                    .stdout
                    .lines()
                    .next()
                    .map(|l| l.trim().to_string())
                    .or_else(|| out.stderr.lines().next().map(|l| l.trim().to_string()));
                info.details.insert(
                    tool.to_string(),
                    ToolAvailability {
                        available: true,
                        version,
                    },
                );
                found.insert(tool.to_string());
            }
            _ => {
                info.details.insert(
                    tool.to_string(),
                    ToolAvailability {
                        available: false,
                        version: None,
                    },
                );
            }
        }
    }
    info.tools = found;

    info
}

fn read_distro() -> Option<String> {
    let p = Path::new("/etc/os-release");
    let content = std::fs::read_to_string(p).ok()?;
    let mut id = None;
    let mut version = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = Some(v.trim().trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("VERSION_CODENAME=") {
            version = Some(v.trim().trim_matches('"').to_string());
        }
    }
    if id.is_none() && version.is_none() {
        return None;
    }
    match (id, version) {
        (Some(i), Some(v)) => Some(format!("{i} {v}")),
        (Some(i), None) => Some(i),
        (None, Some(v)) => Some(v),
        _ => None,
    }
}

fn read_kernel() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

fn read_hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
