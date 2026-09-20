//! v1.1 systemd discovery: user + system units, read-only.
//!
//! Discovers units, enabled/active state, unit file paths, drop-ins, and
//! restart policy where permissions permit. Never mutates. System units are
//! recorded even though reproducing them requires privilege — with an
//! explicit `privileged` classification, not silence.

use configctl_core::classify::{Reproducibility, ResourceClass};
use configctl_core::command::CommandRunner;
use configctl_core::governor::{ResourceGovernor, governed_run};
use std::sync::Arc;

/// Maximum units retained per scope.
pub const MAX_UNITS: usize = 500;
/// Maximum units given the full `show` treatment (bounded subprocesses).
pub const MAX_UNIT_DETAIL: usize = 20;

/// Unit scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitScope {
    User,
    System,
}

/// One systemd unit observation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceRecord {
    pub name: String,
    pub scope: UnitScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_file: Option<String>,
    #[serde(default)]
    pub drop_ins: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wanted_by: Option<String>,
    pub classification: ResourceClass,
    pub reproducibility: Reproducibility,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ServiceInventory {
    pub services: Vec<ServiceRecord>,
    pub user_available: bool,
    pub system_available: bool,
    pub truncated: bool,
    pub warnings: Vec<String>,
}

/// Safe unit names only (prevents hostile `systemctl` output injection).
fn sanitize_unit(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 256 || !s.ends_with(".service") {
        return None;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'))
    {
        return None;
    }
    if s.contains("..") {
        return None;
    }
    Some(s.to_string())
}

fn clean_field(raw: &str) -> Option<String> {
    let s: String = raw.trim().chars().filter(|c| !c.is_control()).collect();
    if s.is_empty() {
        None
    } else {
        Some(s.chars().take(256).collect())
    }
}

struct UnitMaps {
    active: std::collections::BTreeMap<String, String>,
    enabled: std::collections::BTreeMap<String, bool>,
}

/// `list-units` + `list-unit-files` for one scope. Returns `None` when the
/// scope is unavailable (no systemd, no bus, no privilege).
fn probe_scope(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
    user: bool,
) -> Option<UnitMaps> {
    let scope_args = |extra: &[&str]| -> Vec<String> {
        let mut v = Vec::new();
        if user {
            v.push("--user".to_string());
        }
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    };
    let units_out = governed_run(
        governor,
        runner,
        "systemctl",
        scope_args(&[
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager",
        ])
        .iter(),
    )
    .ok()?;
    if units_out.status != Some(0) {
        return None;
    }
    let mut maps = UnitMaps {
        active: std::collections::BTreeMap::new(),
        enabled: std::collections::BTreeMap::new(),
    };
    for line in units_out.stdout.lines() {
        // `name load active sub description...`
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        if let Some(name) = sanitize_unit(cols[0]) {
            if let Some(active) = clean_field(&format!("{}/{}", cols[2], cols[3])) {
                maps.active.insert(name, active);
            }
        }
    }
    // Enabled state is a separate call; failure degrades to unknown.
    if let Ok(files_out) = governed_run(
        governor,
        runner,
        "systemctl",
        scope_args(&[
            "list-unit-files",
            "--type=service",
            "--no-legend",
            "--no-pager",
        ])
        .iter(),
    ) {
        if files_out.status == Some(0) {
            for line in files_out.stdout.lines() {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 2 {
                    continue;
                }
                if let Some(name) = sanitize_unit(cols[0]) {
                    let enabled = matches!(cols[1], "enabled" | "enabled-runtime" | "static");
                    maps.enabled.insert(name, enabled);
                }
            }
        }
    }
    Some(maps)
}

/// Full `show` dump for one unit (bounded; caller caps the count).
fn probe_unit_detail(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
    user: bool,
    name: &str,
) -> (Option<String>, Vec<String>, Option<String>, Option<String>) {
    let mut args = Vec::new();
    if user {
        args.push("--user");
    }
    args.extend(["show", name, "-p", "FragmentPath,DropInPaths,Restart,WantedBy"]);
    let out = match governed_run(governor, runner, "systemctl", args.iter()) {
        Ok(o) if o.status == Some(0) => o,
        _ => return (None, Vec::new(), None, None),
    };
    let mut fragment = None;
    let mut drop_ins = Vec::new();
    let mut restart = None;
    let mut wanted_by = None;
    for line in out.stdout.lines() {
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "FragmentPath" => fragment = clean_field(v),
                "DropInPaths" => {
                    drop_ins = v
                        .split_whitespace()
                        .filter_map(clean_field)
                        .take(16)
                        .collect();
                }
                "Restart" => restart = clean_field(v),
                "WantedBy" => wanted_by = clean_field(v),
                _ => {}
            }
        }
    }
    (fragment, drop_ins, restart, wanted_by)
}

/// Collect user + system service inventory. Read-only; unavailable scopes
/// are recorded, never fatal.
pub fn collect_services(
    governor: &Arc<ResourceGovernor>,
    runner: &dyn CommandRunner,
) -> ServiceInventory {
    let mut inv = ServiceInventory::default();

    for user in [true, false] {
        let scope = if user { UnitScope::User } else { UnitScope::System };
        let Some(maps) = probe_scope(governor, runner, user) else {
            if user {
                inv.user_available = false;
            } else {
                inv.system_available = false;
            }
            continue;
        };
        if user {
            inv.user_available = true;
        } else {
            inv.system_available = true;
        }
        let mut names: Vec<String> = maps
            .active
            .keys()
            .chain(maps.enabled.keys())
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        let mut detail_budget = MAX_UNIT_DETAIL;
        for name in names {
            if inv.services.len() >= MAX_UNITS * 2 {
                inv.truncated = true;
                break;
            }
            let (classification, reproducibility) = if user {
                (ResourceClass::Reproducible, Reproducibility::Reproduce)
            } else {
                (ResourceClass::Privileged, Reproducibility::Observe)
            };
            let mut rec = ServiceRecord {
                name: name.clone(),
                scope,
                enabled: maps.enabled.get(&name).copied(),
                active: maps.active.get(&name).cloned(),
                unit_file: None,
                drop_ins: Vec::new(),
                restart: None,
                wanted_by: None,
                classification,
                reproducibility,
            };
            // Full detail for a bounded subset of user units only; system
            // units stay metadata-level (privilege boundary).
            if user && detail_budget > 0 && governor.limit_hit().is_none() {
                detail_budget -= 1;
                let (fragment, drop_ins, restart, wanted_by) =
                    probe_unit_detail(governor, runner, true, &name);
                rec.unit_file = fragment;
                rec.drop_ins = drop_ins;
                rec.restart = restart;
                rec.wanted_by = wanted_by;
            }
            inv.services.push(rec);
        }
        if governor.limit_hit().is_some() {
            inv.warnings.push(format!(
                "service discovery stopped early: budget exhausted ({})",
                governor.limit_hit().unwrap_or("unknown")
            ));
            break;
        }
    }

    inv.services.sort_by(|a, b| {
        let scope_ord = |s: UnitScope| match s {
            UnitScope::User => 0u8,
            UnitScope::System => 1u8,
        };
        (scope_ord(a.scope), &a.name).cmp(&(scope_ord(b.scope), &b.name))
    });
    if inv.services.len() > MAX_UNITS * 2 {
        inv.services.truncate(MAX_UNITS * 2);
        inv.truncated = true;
    }
    inv
}
