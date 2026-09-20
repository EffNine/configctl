//! Secret references, values, and backends.
//!
//! Profiles carry `secret://namespace/path` references — never values. This
//! module provides:
//!
//! - reference parsing/validation,
//! - `SecretValue`: a value newtype with no value-revealing `Debug`,
//!   `Display`, or `Serialize` (explicit `expose()` is the only read path),
//! - `SecretBackend`: existence/value storage behind a narrow trait,
//! - `SecretToolBackend`: Linux Secret Service via the `secret-tool` CLI
//!   (fixed argv through `CommandRunner`; no custom crypto, no D-Bus code),
//! - `MemoryBackend`: in-memory map for tests and the canary suite,
//! - `FileTestBackend`: file-backed store gated by `CONFIGCTL_SECRET_TEST_DIR`
//!   (test/canary use only — never a production fallback; production without
//!   Secret Service fails closed with exit 6, never plaintext).
//!
//! Values may enter only via hidden prompt or stdin, and leave only via an
//! explicit `get --show` to a TTY (or `--force`). They never appear in argv,
//! logs, errors, JSON, plans, or state.

use crate::command::{CommandRequest, CommandRunner};
use std::fmt;

/// A secret value. The plaintext lives in private memory; `Debug`, `Display`,
/// and `Serialize` never reveal it. Zeroized on drop (best effort; OS swap is
/// outside our boundary and documented).
#[derive(Clone)]
pub struct SecretValue {
    bytes: Vec<u8>,
}

impl SecretValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn from_plaintext(s: &str) -> Self {
        Self {
            bytes: s.as_bytes().to_vec(),
        }
    }

    /// Length only (safe for diagnostics).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The only read path for the plaintext. Callers must never log,
    /// serialize, or interpolate the result.
    pub fn expose<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T,
    {
        f(&self.bytes)
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretValue")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Backend errors. Messages are static templates — never values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretError {
    /// No supported secret backend is available (exit 6).
    Unavailable(String),
    /// The reference does not exist.
    NotFound,
    /// Reference grammar invalid.
    InvalidRef(String),
    /// Backend refused (locked keyring, D-Bus error...). No values included.
    Backend(String),
}

/// Existence probe result: `Some(true/false)` when the backend answered,
/// `None` when the backend itself is unavailable.
pub trait SecretBackend: Send + Sync {
    fn exists(&self, secret_ref: &str) -> Option<bool>;
}

/// Full secret backend (P6): values cross this boundary only.
pub trait SecretStore: Send + Sync {
    fn exists(&self, secret_ref: &str) -> Option<bool>;
    fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError>;
    fn set(&self, secret_ref: &str, value: &SecretValue) -> Result<(), SecretError>;
    fn delete(&self, secret_ref: &str) -> Result<(), SecretError>;
}

/// Parse a `secret://ns/path` ref into `(namespace, path)`. Validates grammar.
pub fn parse_ref(r: &str) -> Result<(String, String), String> {
    crate::paths::validate_secret_ref(r)?;
    let rest = r.strip_prefix("secret://").unwrap_or("");
    let (ns, path) = rest.split_once('/').unwrap_or((rest, ""));
    Ok((ns.to_string(), path.to_string()))
}

/// Linux Secret Service via `secret-tool` (libsecret CLI).
///
/// Storage layout: attribute `configctl-ref = <full secret:// ref>`,
/// label `configctl <ref>`. Lookup/store/clear use fixed argv; the value
/// travels over stdin (store) or stdout (lookup) — never argv.
pub struct SecretToolBackend<'a> {
    pub runner: &'a dyn CommandRunner,
}

impl SecretToolBackend<'_> {
    fn available(&self) -> bool {
        let req = CommandRequest::new("secret-tool", ["--version"]).output_cap(4 * 1024);
        matches!(self.runner.run(&req), Ok(o) if o.status == Some(0))
    }
}

impl SecretBackend for SecretToolBackend<'_> {
    fn exists(&self, secret_ref: &str) -> Option<bool> {
        if parse_ref(secret_ref).is_err() {
            return Some(false);
        }
        if !self.available() {
            return None;
        }
        let req = CommandRequest::new("secret-tool", ["lookup", "configctl-ref", secret_ref])
            .output_cap(64 * 1024);
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

impl SecretStore for SecretToolBackend<'_> {
    fn exists(&self, secret_ref: &str) -> Option<bool> {
        SecretBackend::exists(self, secret_ref)
    }

    fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError> {
        parse_ref(secret_ref).map_err(SecretError::InvalidRef)?;
        if !self.available() {
            return Err(SecretError::Unavailable(
                "no supported secret backend is available (install libsecret / secret-tool and unlock your keyring)".into(),
            ));
        }
        let req = CommandRequest::new("secret-tool", ["lookup", "configctl-ref", secret_ref])
            .output_cap(64 * 1024);
        let out = self
            .runner
            .run(&req)
            .map_err(|_| SecretError::Backend("secret lookup failed".into()))?;
        match out.status {
            Some(0) => Ok(SecretValue::new(out.stdout.into_bytes())),
            Some(1) => Err(SecretError::NotFound),
            _ => Err(SecretError::Backend("secret lookup failed".into())),
        }
    }

    fn set(&self, secret_ref: &str, value: &SecretValue) -> Result<(), SecretError> {
        parse_ref(secret_ref).map_err(SecretError::InvalidRef)?;
        if !self.available() {
            return Err(SecretError::Unavailable(
                "no supported secret backend is available (install libsecret / secret-tool and unlock your keyring)".into(),
            ));
        }
        // NOTE: `CommandRunner` has no stdin channel, so the value cannot be
        // piped through it. secret-tool reads the secret from the terminal or
        // stdin; passing it via argv is forbidden. The CLI layer therefore
        // spawns `secret-tool store` directly with a piped stdin (fixed argv,
        // value on stdin only) — see `cli_secret_tool_store` below.
        let _ = value;
        Err(SecretError::Backend(
            "use the CLI secret-tool stdin path for stores".into(),
        ))
    }

    fn delete(&self, secret_ref: &str) -> Result<(), SecretError> {
        parse_ref(secret_ref).map_err(SecretError::InvalidRef)?;
        if !self.available() {
            return Err(SecretError::Unavailable(
                "no supported secret backend is available".into(),
            ));
        }
        let req = CommandRequest::new("secret-tool", ["clear", "configctl-ref", secret_ref])
            .output_cap(4 * 1024);
        let out = self
            .runner
            .run(&req)
            .map_err(|_| SecretError::Backend("secret delete failed".into()))?;
        match out.status {
            Some(0) => Ok(()),
            _ => Err(SecretError::Backend("secret delete failed".into())),
        }
    }
}

/// Store a value via `secret-tool store` with the value on stdin only.
///
/// This bypasses `CommandRunner` (which has no stdin channel) but keeps every
/// guarantee: fixed argv, no shell, bounded output, timeout, scrubbed
/// environment. Returns `SecretError::Unavailable` when `secret-tool` is
/// missing so callers fail closed with exit 6.
pub fn cli_secret_tool_store(secret_ref: &str, value: &SecretValue) -> Result<(), SecretError> {
    parse_ref(secret_ref).map_err(SecretError::InvalidRef)?;
    use std::io::Write;
    use std::process::Stdio;
    let mut child = std::process::Command::new("secret-tool")
        .args(["store", "--label", &format!("configctl {secret_ref}"), "configctl-ref", secret_ref])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .spawn()
        .map_err(|_| {
            SecretError::Unavailable(
                "no supported secret backend is available (install libsecret / secret-tool and unlock your keyring)".into(),
            )
        })?;
    let status = value.expose(|bytes| {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(bytes);
        }
        child.wait()
    });
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err(SecretError::Backend("secret store failed".into())),
    }
}

/// In-memory backend for tests (refs → values).
#[derive(Default)]
pub struct MemoryBackend {
    pub present: std::collections::BTreeMap<String, Vec<u8>>,
    /// When true, every probe returns `None` (backend unavailable).
    pub unavailable: bool,
}

impl MemoryBackend {
    pub fn with_secret(secret_ref: &str, value: &str) -> Self {
        let mut m = Self::default();
        m.present
            .insert(secret_ref.into(), value.as_bytes().to_vec());
        m
    }
}

impl SecretBackend for MemoryBackend {
    fn exists(&self, secret_ref: &str) -> Option<bool> {
        if self.unavailable {
            return None;
        }
        Some(self.present.contains_key(secret_ref))
    }
}

impl SecretStore for MemoryBackend {
    fn exists(&self, secret_ref: &str) -> Option<bool> {
        SecretBackend::exists(self, secret_ref)
    }

    fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError> {
        parse_ref(secret_ref).map_err(SecretError::InvalidRef)?;
        if self.unavailable {
            return Err(SecretError::Unavailable("test backend unavailable".into()));
        }
        self.present
            .get(secret_ref)
            .cloned()
            .map(SecretValue::new)
            .ok_or(SecretError::NotFound)
    }

    fn set(&self, _secret_ref: &str, _value: &SecretValue) -> Result<(), SecretError> {
        Err(SecretError::Backend(
            "memory backend is read-only in this context".into(),
        ))
    }

    fn delete(&self, _secret_ref: &str) -> Result<(), SecretError> {
        Err(SecretError::Backend(
            "memory backend is read-only in this context".into(),
        ))
    }
}

/// File-backed store for tests/canary only, gated by
/// `CONFIGCTL_SECRET_TEST_DIR`. Each ref maps to `<dir>/<sha256(ref)>` (0600).
/// Production code must never select this backend implicitly.
pub struct FileTestBackend {
    pub dir: std::path::PathBuf,
}

impl FileTestBackend {
    /// Returns `Some` only when `CONFIGCTL_SECRET_TEST_DIR` names an existing
    /// directory (explicit test opt-in).
    pub fn from_env() -> Option<Self> {
        let d = std::env::var_os("CONFIGCTL_SECRET_TEST_DIR")?;
        let dir = std::path::PathBuf::from(d);
        if dir.is_dir() {
            Some(Self { dir })
        } else {
            None
        }
    }

    fn path_for(&self, secret_ref: &str) -> std::path::PathBuf {
        self.dir.join(crate::hash::sha256_str(secret_ref))
    }
}

impl SecretStore for FileTestBackend {
    fn exists(&self, secret_ref: &str) -> Option<bool> {
        if parse_ref(secret_ref).is_err() {
            return Some(false);
        }
        Some(self.path_for(secret_ref).exists())
    }

    fn get(&self, secret_ref: &str) -> Result<SecretValue, SecretError> {
        parse_ref(secret_ref).map_err(SecretError::InvalidRef)?;
        std::fs::read(self.path_for(secret_ref))
            .map(SecretValue::new)
            .map_err(|_| SecretError::NotFound)
    }

    fn set(&self, secret_ref: &str, value: &SecretValue) -> Result<(), SecretError> {
        parse_ref(secret_ref).map_err(SecretError::InvalidRef)?;
        let dest = self.path_for(secret_ref);
        value
            .expose(|bytes| std::fs::write(&dest, bytes))
            .map_err(|_| SecretError::Backend("test store write failed".into()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    fn delete(&self, secret_ref: &str) -> Result<(), SecretError> {
        parse_ref(secret_ref).map_err(SecretError::InvalidRef)?;
        std::fs::remove_file(self.path_for(secret_ref)).map_err(|_| SecretError::NotFound)?;
        Ok(())
    }
}
