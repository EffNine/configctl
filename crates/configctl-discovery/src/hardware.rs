//! v1.1 hardware / system inventory (informational context).
//!
//! Records what the machine *is* so a profile can explain why a target
//! environment may differ. Hardware is classified informational — never
//! "reproduced". All reads are bounded sysfs/proc files; subprocesses go
//! through the governor.

use crate::mounts::MountRecord;
use configctl_core::command::CommandRunner;
use configctl_core::governor::{governed_run, ResourceGovernor};
use std::sync::Arc;

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CpuInfo {
    pub model: Option<String>,
    pub logical_count: usize,
    pub arch: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct MemoryInfo {
    /// Total RAM in KiB (from MemTotal).
    pub total_kib: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GpuInfo {
    pub id: String,
    pub description: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AcceleratorInfo {
    pub cuda: bool,
    pub cuda_version: Option<String>,
    pub rocm: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct HardwareInventory {
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub kernel: Option<String>,
    pub distro: Option<String>,
    pub arch: String,
    /// `uefi`, `bios`, or `unknown` (firmware directory probe only).
    pub boot_mode: String,
    pub root_filesystem: Option<String>,
    pub gpus: Vec<GpuInfo>,
    pub accelerators: AcceleratorInfo,
    /// Compiler toolchain binaries present (filled from the toolchain inventory).
    pub compilers: Vec<String>,
    pub warnings: Vec<String>,
}

fn clean(s: &str, max: usize) -> Option<String> {
    let c: String = s.trim().chars().filter(|c| !c.is_control()).collect();
    if c.is_empty() {
        None
    } else {
        Some(c.chars().take(max).collect())
    }
}

fn read_cpu() -> CpuInfo {
    let mut info = CpuInfo {
        arch: std::env::consts::ARCH.to_string(),
        ..CpuInfo::default()
    };
    let text = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(t) => t,
        Err(_) => return info,
    };
    // Bound the parse: first 64KiB is plenty for model + count.
    let text: String = text.chars().take(65536).collect();
    let mut count = 0usize;
    for line in text.lines() {
        if line.starts_with("processor") {
            count += 1;
        }
        if info.model.is_none() {
            if let Some(v) = line.strip_prefix("model name") {
                info.model = clean(v.trim_start_matches([':', ' ', '\t']), 256);
            }
        }
    }
    info.logical_count = count;
    info
}

fn read_memory() -> MemoryInfo {
    let mut mem = MemoryInfo::default();
    let text = match std::fs::read_to_string("/proc/meminfo") {
        Ok(t) => t,
        Err(_) => return mem,
    };
    for line in text.lines().take(8) {
        if line.starts_with("MemTotal:") {
            if let Some(kb) = line.split_whitespace().nth(1) {
                mem.total_kib = kb.parse::<u64>().unwrap_or(0);
            }
            break;
        }
    }
    mem
}

fn read_distro() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    let mut id = None;
    let mut version = None;
    for line in text.lines().take(32) {
        if let Some(v) = line.strip_prefix("ID=") {
            id = clean(&v.replace('"', ""), 64);
        } else if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version = clean(&v.replace('"', ""), 64);
        }
    }
    match (id, version) {
        (Some(i), Some(v)) => Some(format!("{i} {v}")),
        (Some(i), None) => Some(i),
        _ => None,
    }
}

fn boot_mode() -> String {
    // Presence of efivars ⇒ booted via UEFI. lstat only, never opened.
    if std::fs::symlink_metadata("/sys/firmware/efi").is_ok() {
        "uefi".into()
    } else {
        "unknown".into()
    }
}

/// PCI GPUs from sysfs (class 0x03xxxx), bounded to 64 devices.
fn read_pci_gpus() -> Vec<GpuInfo> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir("/sys/bus/pci/devices") {
        Ok(it) => it.filter_map(|e| e.ok()).take(64).collect::<Vec<_>>(),
        Err(_) => return out,
    };
    for entry in entries {
        let base = entry.path();
        let class = std::fs::read_to_string(base.join("class"))
            .unwrap_or_default()
            .trim()
            .to_string();
        if !(class.starts_with("0x03") || class.starts_with("0x12")) {
            continue;
        }
        let vendor = std::fs::read_to_string(base.join("vendor"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let device = std::fs::read_to_string(base.join("device"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let name = entry.file_name().to_string_lossy().into_owned();
        let id = format!("{name} {vendor}:{device}");
        if let Some(desc) = clean(&id, 128) {
            out.push(GpuInfo {
                id: desc.clone(),
                description: desc,
                source: "sysfs-pci".into(),
            });
        }
        if out.len() >= 16 {
            break;
        }
    }
    out
}

fn read_accelerators(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
) -> AcceleratorInfo {
    let mut acc = AcceleratorInfo::default();
    // NVIDIA device nodes exist ⇒ CUDA-capable hardware present.
    if std::fs::symlink_metadata("/dev/nvidia0").is_ok()
        || std::fs::symlink_metadata("/dev/nvidiactl").is_ok()
    {
        acc.cuda = true;
    }
    // AMD KFD node ⇒ ROCm-capable hardware present.
    if std::fs::symlink_metadata("/dev/kfd").is_ok() {
        acc.rocm = true;
    }
    // Version only via fixed-argv governed probe; absence is not an error.
    if acc.cuda {
        if let Ok(out) = governed_run(
            governor,
            runner,
            "nvidia-smi",
            ["--query-gpu=driver_version", "--format=csv,noheader"].iter(),
        ) {
            if out.status == Some(0) {
                acc.cuda_version = out.stdout.lines().next().and_then(|l| clean(l, 32));
            }
        }
    }
    acc
}

/// Collect hardware/system context. `mounts` supplies the root filesystem
/// type; `compilers` should be the toolchain-derived compiler names.
pub fn collect_hardware(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
    mounts: &[MountRecord],
    compilers: Vec<String>,
) -> HardwareInventory {
    let root_filesystem = mounts
        .iter()
        .filter(|m| !m.pseudo && !m.remote)
        .min_by_key(|m| m.mountpoint.len())
        .map(|m| m.fstype.clone());
    HardwareInventory {
        cpu: read_cpu(),
        memory: read_memory(),
        kernel: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .and_then(|s| clean(&s, 128)),
        distro: read_distro(),
        arch: std::env::consts::ARCH.to_string(),
        boot_mode: boot_mode(),
        root_filesystem,
        gpus: read_pci_gpus(),
        accelerators: read_accelerators(governor, runner),
        compilers,
        warnings: Vec::new(),
    }
}
