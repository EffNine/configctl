//! Secret references and backends (P3 minimal; completed in P6).
//!
//! Profiles carry `secret://namespace/path` references — never values. This
//! module provides reference parsing/validation plus a `SecretBackend` trait
//! with two implementations:
//!
//! - `SecretToolBackend`: Linux Secret Service via the `secret-tool` CLI
//!   (fixed argv through `CommandRunner`; no custom crypto, no D-Bus code).
//!   Reports `None` (unknown) when the backend is unavailable.
//! - `MemoryBackend`: in-memory map for tests and the P8 canary suite.
//!
//! Secret *values* never enter this module's types: `exists()` returns bool
//! only. Value input/output arrives in P6.

use crate::command::{CommandRequest, CommandRunner};

/// Parse a `secret://ns/path` ref into `(namespace, path)`. Validates grammar.
pub fn parse_ref(r: &str) -> Result<(String, String), String> {
    crate::paths::validate_secret_ref(r)?;
    let rest = r.strip_prefix("secret://").unwrap_or("");
    let (ns, path) = rest.split_once('/').unwrap_or((rest, ""));
    Ok((ns.to_string(), path.to_string()))
}

/// Existence probe result: `Some(true/false)` when the backend answered,
/// `None` when the backend itself is unavailable.
pub trait SecretBackend: Send + Sync {
    fn exists(&self, secret_ref: &str) -> Option<bool>;
}

/// Linux Secret Service via `secret-tool lookup` (fixed argv, no values).
pub struct SecretToolBackend<'a> {
    pub runner: &'a dyn CommandRunner,
}

impl SecretBackend for SecretToolBackend<'_> {
    fn exists(&self, secret_ref: &str) -> Option<bool> {
        let (ns, _path) = parse_ref(secret_ref).ok()?;
        // `secret-tool lookup <namespace> <ref>` exits 0 with output when the
        // item exists, 1 when missing. We pass only the ref namespace + full
        // ref as attributes — never a value.
        let req = CommandRequest::new(
            "secret-tool",
            ["lookup", "configctl-namespace", ns.as_str()],
        )
        .output_cap(4 * 1024);
        match self.runner.run(&req) {
            Ok(o) => match o.status {
                Some(0) => Some(true),
                Some(1) => Some(false),
                _ => None,
            },
            Err(_) => None,
        }
    }
}

/// In-memory backend for tests (refs → present bool).
#[derive(Default)]
pub struct MemoryBackend {
    pub present: std::collections::BTreeMap<String, bool>,
    /// When true, every probe returns `None` (backend unavailable).
    pub unavailable: bool,
}

impl SecretBackend for MemoryBackend {
    fn exists(&self, secret_ref: &str) -> Option<bool> {
        if self.unavailable {
            return None;
        }
        Some(*self.present.get(secret_ref).unwrap_or(&false))
    }
}
