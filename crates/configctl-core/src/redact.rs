//! Centralized redaction layer.
//!
//! Every user-visible byte (terminal output, JSON, logs, errors) flows
//! through this layer. Redaction is layered and fail-closed:
//!
//! 1. **Type-level** — redacted representations only; no type that may hold
//!    a value implements `Debug`/`Display` over the value.
//! 2. **Registry-level** — exact occurrences of registered values are
//!    replaced with `<redacted>`.
//! 3. **Pattern-level** — known token shapes are masked even if the value is
//!    not registry-known (short prefix preserved, e.g. `sk-****`).
//! 4. **Error-level** — error messages are built from static templates with
//!    non-secret arguments only.

use serde::{Serialize, Serializer};
use std::collections::BTreeSet;
use std::fmt;

/// Marker placeholder used for all redacted values.
pub const REDACTED: &str = "<redacted>";

/// A value that must never appear verbatim in any output.
///
/// Construction consumes the plaintext; only a length-based hint is retained,
/// so no reference to the content outlives the parse step. `Debug`,
/// `Display`, and `Serialize` never reveal the value.
#[derive(Clone)]
pub struct SecretValue {
    hint: String,
}

impl SecretValue {
    /// Consumes the plaintext; only a length-based hint is retained.
    pub fn new(value: &str) -> Self {
        Self {
            hint: format!("value(len={})", value.len()),
        }
    }

    /// The retained hint (length only). Safe to render.
    pub fn hint(&self) -> &str {
        &self.hint
    }

    /// True when the underlying value is empty.
    pub fn is_empty(&self) -> bool {
        self.hint == "value(len=0)"
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately never reveals content; derived Debug would be unsafe.
        f.debug_struct("SecretValue")
            .field("hint", &self.hint)
            .finish()
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for SecretValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

/// Process-local registry of values to redact.
///
/// Thread-safe; held for the duration of one command. Registration is the
/// only way a value becomes known to the redactor. `Clone` shares the
/// underlying state (Arc over a Mutex), so clones redact identically.
#[derive(Clone, Default)]
pub struct SecretRegistry {
    inner: std::sync::Arc<std::sync::Mutex<RegistryInner>>,
}

#[derive(Default)]
struct RegistryInner {
    exact: BTreeSet<String>,
    /// Pattern-family prefixes masked even when the value was not registered
    /// exactly (pattern-level layer), e.g. `sk-`, `ghp_`, `xoxb-`.
    prefixes: BTreeSet<String>,
}

impl SecretRegistry {
    /// Register an exact value for redaction (registry-level layer).
    ///
    /// Values shorter than 4 characters are not registered: they carry no
    /// secret signal and would over-redact common strings.
    pub fn register(&self, value: &str) {
        if value.len() < 4 {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.exact.insert(value.to_string());
    }

    /// Register a known token-family prefix (pattern-level layer).
    pub fn register_pattern_prefix(&self, prefix: &str) {
        if prefix.is_empty() {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.prefixes.insert(prefix.to_string());
    }

    /// Number of registered exact values (diagnostic only).
    pub fn registered_count(&self) -> usize {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.exact.len()
    }

    /// Snapshot registered values for in-memory safety checks (e.g. the P2
    /// post-write leak check). The values never leave the process; callers
    /// must never serialize, log, or render them.
    pub fn snapshot_values(&self) -> Vec<String> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.exact.iter().cloned().collect()
    }

    /// Redact `text`: replace every exact-registered value with `<redacted>`
    /// and mask whitespace-delimited tokens that start with a registered
    /// prefix (`prefix` + `****`). Idempotent; running it twice yields the
    /// same result as running it once.
    pub fn redact(&self, text: &str) -> String {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = text.to_string();
        for v in g.exact.iter() {
            if out.contains(v) {
                out = out.replacen(v, REDACTED, usize::MAX);
            }
        }
        for p in g.prefixes.iter() {
            if out.contains(p) {
                out = mask_tokens_with_prefix(&out, p);
            }
        }
        out
    }
}

/// Replace each whitespace-delimited token that starts with `prefix` with
/// `prefix` + `****`. Whitespace runs are collapsed to single spaces.
/// Idempotent: an already-masked token (`prefix****`) has no extra
/// characters after the prefix, so it is emitted verbatim.
fn mask_tokens_with_prefix(text: &str, prefix: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut first = true;
    for token in text.split_whitespace() {
        if !first {
            out.push(' ');
        }
        first = false;
        if token.starts_with(prefix) && token.len() > prefix.len() {
            out.push_str(prefix);
            out.push_str("****");
        } else {
            out.push_str(token);
        }
    }
    out
}

/// Redact `text` using the registry, then mask every `needle` occurrence as
/// `prefix****` (pattern-level layer for known token families the detector
/// reported).
pub fn redact_with_patterns(
    registry: &SecretRegistry,
    text: &str,
    patterns: &[(&str, &str)],
) -> String {
    let mut out = registry.redact(text);
    for (needle, prefix) in patterns {
        if out.contains(needle) {
            let masked = format!("{prefix}****");
            out = out.replacen(needle, &masked, usize::MAX);
        }
    }
    out
}
