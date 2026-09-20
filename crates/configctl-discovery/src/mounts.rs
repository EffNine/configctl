//! v1.1 mount-aware scanning: discover mounts first, then decide traversal.
//!
//! The scanner records every mount boundary explicitly. Network mounts and
//! kernel pseudo-filesystems are classified (`record`, not recursively
//! scanned unless explicitly enabled) instead of being silently absent.

/// One mount table entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MountRecord {
    pub mountpoint: String,
    pub fstype: String,
    pub device: String,
    #[serde(default)]
    pub options: Vec<String>,
    /// True for network filesystems (nfs, smb/cifs, 9p, sshfs, afs…).
    pub remote: bool,
    /// True for kernel pseudo-filesystems (proc, sysfs, cgroup, tmpfs…).
    pub pseudo: bool,
}

/// Traversal decision for one mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountDecision {
    /// Descend normally.
    Scan,
    /// Record metadata only; do not recurse.
    RecordOnly,
}

impl MountDecision {
    pub fn reason(self) -> &'static str {
        match self {
            MountDecision::Scan => "local filesystem",
            MountDecision::RecordOnly => "external or pseudo filesystem",
        }
    }
}

const REMOTE_FSTYPES: &[&str] = &[
    "nfs",
    "nfs4",
    "smbfs",
    "cifs",
    "smb3",
    "9p",
    "afs",
    "ncpfs",
    "fuse.sshfs",
    "sshfs",
    "glusterfs",
    "ceph",
    "lustre",
];

const PSEUDO_FSTYPES: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "cgroup",
    "cgroup2",
    "debugfs",
    "tracefs",
    "securityfs",
    "configfs",
    "fusectl",
    "pstore",
    "bpf",
    "autofs",
    "mqueue",
    "hugetlbfs",
    "overlay",
    "nsfs",
];

// Note: `overlay` (containers) is listed pseudo because descending from the
// host into every container layer mount is a mount explosion by default;
// the mount itself is still recorded with its type.
pub fn is_remote_fstype(fstype: &str) -> bool {
    REMOTE_FSTYPES.contains(&fstype)
}

pub fn is_pseudo_fstype(fstype: &str) -> bool {
    PSEUDO_FSTYPES.contains(&fstype)
}

/// Decide traversal for one mount under the given policy flags.
pub fn decide(mount: &MountRecord, follow_mounts: bool, scan_network: bool) -> MountDecision {
    if mount.pseudo {
        return MountDecision::RecordOnly;
    }
    if mount.remote && !scan_network {
        return MountDecision::RecordOnly;
    }
    if follow_mounts {
        return MountDecision::Scan;
    }
    // Default: stay on the scan-root filesystem (the walker enforces the
    // device boundary); other local mounts are recorded, not descended into.
    // The root filesystem itself always scans — callers skip the boundary
    // check for the root device.
    MountDecision::Scan
}

/// Parse `/proc/self/mountinfo` (preferred: unescaped fields) with fallback
/// to `/proc/mounts`. Returns an empty vec when neither is readable.
pub fn collect() -> Vec<MountRecord> {
    if let Some(records) = parse_mountinfo() {
        return records;
    }
    parse_mounts_fallback()
}

fn parse_mountinfo() -> Option<Vec<MountRecord>> {
    let text = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        // mountinfo: `id parent major:minor root mountpoint options ... - fstype source superoptions`
        let sep = line.find(" - ")?;
        let (pre, post) = (&line[..sep], &line[sep + 3..]);
        let pre_fields: Vec<&str> = pre.split_whitespace().collect();
        if pre_fields.len() < 6 {
            continue;
        }
        let mountpoint = unescape_mount_path(pre_fields[4]);
        let post_fields: Vec<&str> = post.split_whitespace().collect();
        if post_fields.len() < 3 {
            continue;
        }
        let fstype = post_fields[0].to_string();
        let device = post_fields[1].to_string();
        let options: Vec<String> = pre_fields[5].split(',').map(|s| s.to_string()).collect();
        out.push(MountRecord {
            remote: is_remote_fstype(&fstype),
            pseudo: is_pseudo_fstype(&fstype),
            mountpoint,
            fstype,
            device,
            options,
        });
        if out.len() > 10000 {
            break;
        }
    }
    if out.is_empty() {
        return None;
    }
    out.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));
    Some(out)
}

fn parse_mounts_fallback() -> Vec<MountRecord> {
    let text = match std::fs::read_to_string("/proc/mounts") {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let fstype = fields[2].to_string();
        out.push(MountRecord {
            remote: is_remote_fstype(&fstype),
            pseudo: is_pseudo_fstype(&fstype),
            device: unescape_mount_path(fields[0]),
            mountpoint: unescape_mount_path(fields[1]),
            fstype,
            options: fields[3].split(',').map(|s| s.to_string()).collect(),
        });
        if out.len() > 10000 {
            break;
        }
    }
    out.sort_by(|a, b| a.mountpoint.cmp(&b.mountpoint));
    out
}

/// mountinfo escapes spaces as `\040` (octal). Decode defensively.
fn unescape_mount_path(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let oct: String = chars.by_ref().take(3).collect();
            if oct.len() == 3 {
                if let Ok(byte) = u8::from_str_radix(&oct, 8) {
                    out.push(byte as char);
                    continue;
                }
                out.push('\\');
                out.push_str(&oct);
            } else {
                out.push('\\');
                out.push_str(&oct);
            }
        } else {
            out.push(c);
        }
    }
    // Never allow NUL or control characters into records.
    out.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod mount_tests {
    use super::*;

    #[test]
    fn fstype_buckets() {
        assert!(is_remote_fstype("nfs"));
        assert!(is_remote_fstype("cifs"));
        assert!(!is_remote_fstype("ext4"));
        assert!(is_pseudo_fstype("proc"));
        assert!(is_pseudo_fstype("cgroup2"));
        assert!(!is_pseudo_fstype("xfs"));
    }

    #[test]
    fn policy_defaults_to_record_only_for_remote_and_pseudo() {
        let nfs = MountRecord {
            mountpoint: "/mnt/nfs".into(),
            fstype: "nfs".into(),
            device: "srv:/x".into(),
            options: vec![],
            remote: true,
            pseudo: false,
        };
        assert_eq!(decide(&nfs, false, false), MountDecision::RecordOnly);
        assert_eq!(decide(&nfs, true, true), MountDecision::Scan);
        let proc = MountRecord {
            mountpoint: "/proc".into(),
            fstype: "proc".into(),
            device: "proc".into(),
            options: vec![],
            remote: false,
            pseudo: true,
        };
        assert_eq!(decide(&proc, true, true), MountDecision::RecordOnly);
    }

    #[test]
    fn collect_parses_host_mounts() {
        // Must terminate and return well-formed records on any Linux host.
        let mounts = collect();
        assert!(mounts.len() < 10000);
        for m in &mounts {
            assert!(!m.mountpoint.is_empty());
            assert!(!m.fstype.is_empty());
            assert!(m.mountpoint.starts_with('/'));
        }
    }
}
