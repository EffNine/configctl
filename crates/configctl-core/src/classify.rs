//! v1.1 first-class resource classification model.
//!
//! Core principle: `unknown → discover → classify UNKNOWN → preserve metadata`.
//! Nothing discovered is silently dropped: every resource gets an identity,
//! a type, a classification with evidence (`signals`), a reproducibility
//! state, and an explicit capture decision with a reason.
//!
//! This module is pure (no I/O): discovery subsystems call [`classify_file`]
//! / [`classify_env_var`] and store the resulting [`Classification`] next to
//! the resource. Capture planning consumes [`CaptureAction`] + reason.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Every discovered resource lands in exactly one class.
///
/// `Unknown` is a first-class bucket — it means "observed but not yet
/// understood", never "ignored".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceClass {
    /// Safe to copy across machines (shell config, editor config, manifests).
    Portable,
    /// Regenerable from a recipe rather than copied (lockfiles from manifests).
    Reproducible,
    /// Tied to this machine (hostnames, absolute user paths, hardware IDs).
    MachineSpecific,
    /// Build output (`target/`, `node_modules/`, `dist/`, …).
    Generated,
    /// Cache content (`.cache/`, `__pycache__/`, registry caches, …).
    Cache,
    /// Third-party dependency content (vendored deps, VCS metadata, …).
    Dependency,
    /// Secret material itself (private keys, tokens, `.env` values).
    Secret,
    /// Credential metadata or containers (`.ssh/config`, `*.pub`, helpers).
    Credential,
    /// Requires privilege to read or reproduce (system units, `/etc`…).
    Privileged,
    /// Observed but not representable in the profile model.
    Unsupported,
    /// Observed, evidence recorded, semantics not yet understood.
    Unknown,
}

impl ResourceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceClass::Portable => "portable",
            ResourceClass::Reproducible => "reproducible",
            ResourceClass::MachineSpecific => "machine_specific",
            ResourceClass::Generated => "generated",
            ResourceClass::Cache => "cache",
            ResourceClass::Dependency => "dependency",
            ResourceClass::Secret => "secret",
            ResourceClass::Credential => "credential",
            ResourceClass::Privileged => "privileged",
            ResourceClass::Unsupported => "unsupported",
            ResourceClass::Unknown => "unknown",
        }
    }
}

/// What reproduction means for a classified resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reproducibility {
    /// Bytes can be reproduced on the target machine.
    Reproduce,
    /// Only a `secret://` reference is stored; value comes from the backend.
    Reference,
    /// Recorded as observed state; not reproduced.
    Observe,
    /// Requires a human step (documented, never automated blindly).
    Manual,
    /// Cannot be reproduced by configctl.
    Unsupported,
}

/// Explicit capture decision. There is no implicit default: every resource
/// in a profile or report carries an action **and** a reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureAction {
    /// Copy content into the profile bundle.
    Capture,
    /// Store a `secret://` reference only.
    Reference,
    /// Store metadata only (exists, type, size, provenance).
    Observe,
    /// Record presence + reason for exclusion.
    Exclude,
}

/// Filesystem object type. Special files are recorded, never read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Socket,
    Fifo,
    BlockDevice,
    CharDevice,
    Unknown,
}

impl FileKind {
    /// Map `std::fs::FileType` (which cannot see devices/FIFOs/sockets
    /// differences beyond dir/file/symlink) plus mode bits to a [`FileKind`].
    /// `mode` is the raw `st_mode` when available (Unix), else `None`.
    pub fn from_file_type(ft: &std::fs::FileType, mode: Option<u32>) -> Self {
        if ft.is_symlink() {
            return FileKind::Symlink;
        }
        if ft.is_dir() {
            return FileKind::Directory;
        }
        // Special files (sockets, FIFOs, devices) report false for
        // `is_file()` — consult the raw mode bits first.
        if let Some(m) = mode {
            // S_IFMT mask + type codes (POSIX).
            match m & 0o170000 {
                0o140000 => return FileKind::Socket,
                0o010000 => return FileKind::Fifo,
                0o060000 => return FileKind::BlockDevice,
                0o020000 => return FileKind::CharDevice,
                _ => {}
            }
        }
        if ft.is_file() {
            return FileKind::Regular;
        }
        FileKind::Unknown
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FileKind::Regular => "regular",
            FileKind::Directory => "directory",
            FileKind::Symlink => "symlink",
            FileKind::Socket => "socket",
            FileKind::Fifo => "fifo",
            FileKind::BlockDevice => "block_device",
            FileKind::CharDevice => "char_device",
            FileKind::Unknown => "unknown",
        }
    }

    /// True for types configctl must never open/read.
    pub fn is_special(self) -> bool {
        matches!(
            self,
            FileKind::Socket | FileKind::Fifo | FileKind::BlockDevice | FileKind::CharDevice
        )
    }
}

/// A classification verdict with machine-checkable evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    pub class: ResourceClass,
    pub reproducibility: Reproducibility,
    pub action: CaptureAction,
    /// Short evidence tokens, e.g. `generated_dir:target`, `secret_name:id_rsa`.
    pub signals: Vec<String>,
    /// Human-readable reason for the capture action (required, never empty).
    pub reason: String,
}

impl Classification {
    fn new(
        class: ResourceClass,
        reproducibility: Reproducibility,
        action: CaptureAction,
        signals: Vec<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            class,
            reproducibility,
            action,
            signals,
            reason: reason.into(),
        }
    }
}

/// Directory names whose content is build output (matched on any component).
pub const GENERATED_DIRS: &[&str] = &[
    "target",
    "node_modules",
    "dist",
    "build",
    "out",
    "_build",
    "deps",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
    ".next",
    ".nuxt",
    ".gradle",
    ".idea", // editor project cache — generated, not source
    "coverage",
    ".coverage",
];

/// Directory names whose content is cache (matched on any component).
pub const CACHE_DIRS: &[&str] = &[
    ".cache",
    ".npm",
    ".yarn",
    ".pnpm-store",
    "__pycache__",
    ".cargo_registry",
    ".cargo-git",
    ".nuget",
    ".m2",
    ".ivy2",
    ".gradle-caches",
];

/// Filenames that bear secrets or credentials (exact basename match,
/// case-sensitive like the filesystem).
pub const SECRET_BASENAMES: &[&str] = &[
    "id_ed25519",
    "id_rsa",
    "id_ecdsa",
    "id_dsa",
    "id_ed25519_sk",
    "id_ecdsa_sk",
    ".env",
    ".env.local",
    "credentials",
    "secrets",
    "passwd",
    "shadow",
    "keystore",
    "truststore",
    ".git-credentials",
    ".netrc",
    "_netrc",
    ".vault-token",
    "kubeconfig",
    "config", // only secret-bearing under credential dirs; see below
];

/// Extensions that indicate secret material.
pub const SECRET_EXTENSIONS: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".jks", ".asc", ".gpg"];

/// Classify a filesystem path (no I/O; pure name/location heuristics).
///
/// `executable` marks owner-executable regular files (toolchain binaries,
/// scripts). Callers add content/ownership signals by pushing to
/// [`Classification::signals`] afterwards.
pub fn classify_file(path: &Path, kind: FileKind, executable: bool) -> Classification {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let components: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();

    // 1. Special files: observed, never read.
    if kind.is_special() {
        return Classification::new(
            ResourceClass::Unsupported,
            Reproducibility::Observe,
            CaptureAction::Observe,
            vec![format!("special_file:{}", kind.as_str())],
            format!("{} file recorded as observed; never opened", kind.as_str()),
        );
    }

    // 2. Symlinks are classified by relationship (target analysis happens in
    //    the symlink mapper); default to observe.
    if kind == FileKind::Symlink {
        return Classification::new(
            ResourceClass::Unknown,
            Reproducibility::Observe,
            CaptureAction::Observe,
            vec!["symlink".to_string()],
            "symlink relationship recorded; target classified separately",
        );
    }

    // 3. Secret-bearing basenames.
    if SECRET_BASENAMES.iter().any(|b| *b == name) && name != "config" {
        return Classification::new(
            ResourceClass::Secret,
            Reproducibility::Reference,
            CaptureAction::Reference,
            vec![format!("secret_name:{name}")],
            "secret-bearing filename; value never stored, reference only",
        );
    }
    // `config` is only credential-adjacent under known credential dirs.
    if name == "config"
        && components
            .iter()
            .any(|c| c == ".ssh" || c == ".gnupg" || c == ".aws" || c == ".kube")
    {
        return Classification::new(
            ResourceClass::Credential,
            Reproducibility::Observe,
            CaptureAction::Observe,
            vec!["credential_config".to_string()],
            "credential configuration metadata observed, material not captured",
        );
    }
    if SECRET_EXTENSIONS.iter().any(|e| name.ends_with(e)) {
        // `.pub` companions are metadata, not secrets.
        if name.ends_with(".pub") {
            return Classification::new(
                ResourceClass::Credential,
                Reproducibility::Reproduce,
                CaptureAction::Capture,
                vec!["public_key".to_string()],
                "public key material is safe to capture",
            );
        }
        return Classification::new(
            ResourceClass::Secret,
            Reproducibility::Reference,
            CaptureAction::Reference,
            vec![format!("secret_extension:{name}")],
            "secret-bearing extension; value never stored, reference only",
        );
    }
    if name.ends_with(".pub") {
        return Classification::new(
            ResourceClass::Credential,
            Reproducibility::Reproduce,
            CaptureAction::Capture,
            vec!["public_key".to_string()],
            "public key material is safe to capture",
        );
    }
    // Private OpenSSH key names without extension.
    if name.starts_with("id_") && !name.contains('.') {
        return Classification::new(
            ResourceClass::Secret,
            Reproducibility::Reference,
            CaptureAction::Reference,
            vec![format!("private_key:{name}")],
            "private key material never captured; existence recorded",
        );
    }

    // 4. Generated / cache content (any path component).
    if let Some(hit) = GENERATED_DIRS.iter().find(|d| components.iter().any(|c| c == *d)) {
        return Classification::new(
            ResourceClass::Generated,
            Reproducibility::Reproduce,
            CaptureAction::Exclude,
            vec![format!("generated_dir:{hit}")],
            format!("generated build artifact under `{hit}/`; excluded from reproduction"),
        );
    }
    if let Some(hit) = CACHE_DIRS.iter().find(|d| components.iter().any(|c| c == *d)) {
        return Classification::new(
            ResourceClass::Cache,
            Reproducibility::Unsupported,
            CaptureAction::Exclude,
            vec![format!("cache_dir:{hit}")],
            format!("cache content under `{hit}/`; excluded from reproduction"),
        );
    }

    // 5. VCS metadata: recorded for provenance, not captured as files.
    if components.iter().any(|c| c == ".git") {
        return Classification::new(
            ResourceClass::Dependency,
            Reproducibility::Observe,
            CaptureAction::Observe,
            vec!["vcs_metadata".to_string()],
            "VCS metadata observed for provenance; history not captured as files",
        );
    }

    // 6. Lockfiles are reproducible-from-manifest, portable as text.
    if is_lockfile(&name) {
        return Classification::new(
            ResourceClass::Reproducible,
            Reproducibility::Reproduce,
            CaptureAction::Capture,
            vec!["lockfile".to_string()],
            "lockfile captured; regenerable from manifest",
        );
    }

    // 7. Executables: toolchain content, provenance tracked elsewhere.
    if executable && kind == FileKind::Regular {
        return Classification::new(
            ResourceClass::Dependency,
            Reproducibility::Reproduce,
            CaptureAction::Observe,
            vec!["executable".to_string()],
            "executable observed; reproduced via package/toolchain provenance",
        );
    }

    // 8. Default: UNKNOWN with evidence — never silently dropped.
    let mut signals = vec!["unclassified".to_string()];
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        signals.push(format!("extension:.{ext}"));
    }
    Classification::new(
        ResourceClass::Unknown,
        Reproducibility::Observe,
        CaptureAction::Observe,
        signals,
        "observed but semantics not yet understood; metadata preserved",
    )
}

/// Lockfile basenames (regenerable from their manifest).
fn is_lockfile(name: &str) -> bool {
    matches!(
        name,
        "Cargo.lock"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "uv.lock"
            | "poetry.lock"
            | "Pdm.lock"
            | "go.sum"
            | "Gemfile.lock"
            | "composer.lock"
            | "mix.lock"
            | "requirements.txt"
    )
}

/// Environment variable classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvClass {
    PublicConfig,
    Path,
    Runtime,
    Secret,
    MachineSpecific,
    Unknown,
}

impl EnvClass {
    pub fn as_str(self) -> &'static str {
        match self {
            EnvClass::PublicConfig => "public_config",
            EnvClass::Path => "path",
            EnvClass::Runtime => "runtime",
            EnvClass::Secret => "secret",
            EnvClass::MachineSpecific => "machine_specific",
            EnvClass::Unknown => "unknown",
        }
    }
}

/// Classify an environment variable by name (never by value).
pub fn classify_env_var(name: &str) -> EnvClass {
    let upper = name.to_uppercase();
    // Secrets first — never persist raw values for these.
    if upper.contains("PASSWORD")
        || upper.contains("SECRET")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("PASSPHRASE")
        || upper.contains("TOKEN")
        || upper == "AWS_SECRET_ACCESS_KEY"
        || upper == "AWS_SESSION_TOKEN"
        || upper.ends_with("_KEY")
        || upper.ends_with("_SECRET")
    {
        // `_KEY` alone also matches public keys (e.g. `SSH_KEY_PATH`);
        // those are paths, not secrets.
        if upper.ends_with("_PATH") || upper.ends_with("_FILE") || upper.ends_with("_DIR") {
            return EnvClass::Path;
        }
        return EnvClass::Secret;
    }
    if name == "PATH"
        || name == "LD_LIBRARY_PATH"
        || name == "MANPATH"
        || name == "XDG_DATA_DIRS"
        || name.ends_with("PATH")
            && matches!(
                upper.as_str(),
                "CPATH" | "PKG_CONFIG_PATH" | "CMAKE_PREFIX_PATH" | "NODE_PATH" | "PYTHONPATH"
            )
    {
        return EnvClass::Path;
    }
    if matches!(
        upper.as_str(),
        "HOME" | "USER" | "HOSTNAME" | "HOST" | "MACHINE" | "DISPLAY" | "XDG_RUNTIME_DIR" | "DBUS_SESSION_BUS_ADDRESS"
    ) || upper.starts_with("XDG_")
        || upper == "SHELL"
        || upper == "TERM_PROGRAM"
    {
        return EnvClass::MachineSpecific;
    }
    if matches!(
        upper.as_str(),
        "LANG"
            | "LC_ALL"
            | "LC_CTYPE"
            | "TZ"
            | "EDITOR"
            | "VISUAL"
            | "PAGER"
            | "TERM"
            | "CI"
            | "CONTINUOUS_INTEGRATION"
            | "RUST_LOG"
            | "RUST_BACKTRACE"
            | "NO_COLOR"
            | "CLICOLOR"
    ) || upper.starts_with("CARGO_")
        || upper.starts_with("RUST")
        || upper.starts_with("GO")
        || upper.starts_with("NODE_")
        || upper.starts_with("NPM_")
        || upper.starts_with("PYTHON")
    {
        // Toolchain tuning knobs are portable config…
        return EnvClass::PublicConfig;
    }
    if upper == "PWD"
        || upper == "OLDPWD"
        || upper == "SHLVL"
        || upper == "_"
        || upper.starts_with("LS_COLORS")
    {
        return EnvClass::Runtime;
    }
    EnvClass::Unknown
}

/// Execution-side policy class for a classified resource.
///
/// Discovery/capture is hardcore; the **execution engine** still refuses to
/// treat every reproducible resource as safe to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlanActionClass {
    SafeReproduce,
    Privileged,
    Destructive,
    MachineSpecific,
    SecretRequired,
    Unsupported,
    Manual,
}

impl PlanActionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanActionClass::SafeReproduce => "SAFE_REPRODUCE",
            PlanActionClass::Privileged => "PRIVILEGED",
            PlanActionClass::Destructive => "DESTRUCTIVE",
            PlanActionClass::MachineSpecific => "MACHINE_SPECIFIC",
            PlanActionClass::SecretRequired => "SECRET_REQUIRED",
            PlanActionClass::Unsupported => "UNSUPPORTED",
            PlanActionClass::Manual => "MANUAL",
        }
    }
}

/// Map a classification to its execution-side policy class.
pub fn plan_class_for(c: &Classification) -> PlanActionClass {
    match c.class {
        ResourceClass::Secret => PlanActionClass::SecretRequired,
        ResourceClass::Credential => PlanActionClass::Manual,
        ResourceClass::Privileged => PlanActionClass::Privileged,
        ResourceClass::MachineSpecific => PlanActionClass::MachineSpecific,
        ResourceClass::Generated | ResourceClass::Cache => PlanActionClass::Unsupported,
        ResourceClass::Unsupported => PlanActionClass::Unsupported,
        ResourceClass::Unknown => PlanActionClass::Manual,
        ResourceClass::Portable | ResourceClass::Reproducible | ResourceClass::Dependency => {
            PlanActionClass::SafeReproduce
        }
    }
}
