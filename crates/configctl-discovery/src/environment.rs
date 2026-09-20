//! v1.1 environment variable mapping (metadata only, never values).
//!
//! Every variable is classified by name via [`classify_env_var`]. Raw values
//! are never persisted — with two narrow exceptions: PATH-like variables get
//! entry decomposition (ordering, duplicates, missing entries), and a tight
//! allowlist of display-safe names keeps a truncated value for context.

use configctl_core::classify::{EnvClass, classify_env_var};
use std::collections::BTreeMap;
use std::path::Path;

/// Names whose values are display-safe by construction (fixed locale/tool
/// output tokens, never credentials). Values still truncated to 128 chars.
const SAFE_VALUE_NAMES: &[&str] = &[
    "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "EDITOR", "VISUAL", "PAGER", "TERM",
    "CI", "CONTINUOUS_INTEGRATION", "NO_COLOR", "CLICOLOR", "RUST_BACKTRACE",
];

/// Variables decomposed into path entries instead of stored raw.
fn is_path_like(name: &str) -> bool {
    name == "PATH"
        || name == "MANPATH"
        || name == "LD_LIBRARY_PATH"
        || name == "XDG_DATA_DIRS"
        || matches!(
            name,
            "CPATH" | "PKG_CONFIG_PATH" | "CMAKE_PREFIX_PATH" | "NODE_PATH" | "PYTHONPATH"
        )
}

/// PATH entry analysis: ordering preserved, duplicates + missing flagged,
// user/system origin split by $HOME prefix.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PathAnalysis {
    pub entries: Vec<String>,
    #[serde(default)]
    pub duplicates: Vec<String>,
    #[serde(default)]
    pub missing: Vec<String>,
    #[serde(default)]
    pub user_entries: Vec<String>,
    #[serde(default)]
    pub system_entries: Vec<String>,
}

pub fn analyze_path_value(raw: &str, home: Option<&str>) -> PathAnalysis {
    let mut entries = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut duplicates = Vec::new();
    let mut missing = Vec::new();
    let mut user_entries = Vec::new();
    let mut system_entries = Vec::new();
    for entry in raw.split(':') {
        if entry.is_empty() {
            continue;
        }
        // Cap total entries so a hostile PATH cannot blow up the report.
        if entries.len() >= 256 {
            break;
        }
        let clean: String = entry.chars().filter(|c| !c.is_control()).take(512).collect();
        if clean.is_empty() || clean.len() > 512 {
            continue;
        }
        if !seen.insert(clean.clone()) && !duplicates.contains(&clean) {
            duplicates.push(clean.clone());
        }
        if !Path::new(&clean).exists() && !missing.contains(&clean) {
            missing.push(clean.clone());
        }
        match home {
            Some(h) if clean == h || clean.starts_with(&format!("{h}/")) => {
                user_entries.push(clean.clone())
            }
            _ => system_entries.push(clean.clone()),
        }
        entries.push(clean);
    }
    duplicates.sort();
    missing.sort();
    PathAnalysis {
        entries,
        duplicates,
        missing,
        user_entries,
        system_entries,
    }
}

/// One mapped environment variable (name + classification + metadata).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnvVarRecord {
    pub name: String,
    pub classification: EnvClass,
    /// Truncated value, only for [`SAFE_VALUE_NAMES`]; otherwise absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Entry decomposition, only for PATH-like variables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_analysis: Option<PathAnalysis>,
}

/// Whole-process environment inventory (metadata only).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct EnvironmentInventory {
    pub vars: Vec<EnvVarRecord>,
    pub total: usize,
    pub secrets: usize,
    pub by_class: BTreeMap<String, usize>,
}

/// Map the current process environment. Values are never stored except for
/// the display-safe allowlist (truncated) and PATH decomposition.
pub fn collect_environment() -> EnvironmentInventory {
    let home = std::env::var_os("HOME").map(|h| h.to_string_lossy().into_owned());
    let mut inv = EnvironmentInventory::default();
    let mut vars: Vec<(String, String)> = Vec::new();
    for (k, v) in std::env::vars_os() {
        let name = k.to_string_lossy().into_owned();
        if name.is_empty() || name.len() > 256 || name.chars().any(|c| c.is_control()) {
            continue;
        }
        // Cap the count so pathological environments stay bounded.
        if vars.len() >= 4096 {
            break;
        }
        vars.push((name, v.to_string_lossy().into_owned()));
    }
    vars.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, value) in vars {
        let class = classify_env_var(&name);
        *inv.by_class.entry(class.as_str().to_string()).or_insert(0) += 1;
        if class == EnvClass::Secret {
            inv.secrets += 1;
        }
        let value_opt = if SAFE_VALUE_NAMES.contains(&name.as_str()) {
            Some(value.chars().filter(|c| !c.is_control()).take(128).collect())
        } else {
            None
        };
        let path_analysis = if is_path_like(&name) {
            Some(analyze_path_value(&value, home.as_deref()))
        } else {
            None
        };
        inv.vars.push(EnvVarRecord {
            name,
            classification: class,
            value: value_opt,
            path_analysis,
        });
    }
    inv.total = inv.vars.len();
    inv
}
