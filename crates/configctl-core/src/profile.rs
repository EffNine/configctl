//! P2 declarative profile model (typed, TOML-serializable).
//!
//! The profile represents **desired reproducible state**, not a machine dump.
//! Secret values can never be represented: only names, classifications, and
//! `secret://` references exist in this model.

use crate::paths;
use serde::{Deserialize, Serialize};

/// Current profile schema version. Files with any other version are refused.
pub const SCHEMA_VERSION: u32 = 1;

/// A full declarative profile (maps to `profile.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Must equal [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Profile name (`[a-z0-9][a-z0-9-_]{0,63}`).
    pub name: String,
    /// Free text, ≤ 512 chars.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Informational producer version; ignored for semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configctl_version: Option<String>,
    /// Capture metadata (informational; excluded from reproducibility).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    /// Platform the profile was captured on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    /// Desired packages (names only; versions live in `packages.lock.toml`).
    #[serde(default)]
    pub packages: Packages,
    /// Managed files.
    #[serde(default)]
    pub files: Vec<FileEntry>,
    /// Global non-secret literals (P2 emits none; reserved for P3+).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<std::collections::BTreeMap<String, EnvLiteral>>,
    /// User services (P2 emits none; discovery has no service probing yet).
    #[serde(default)]
    pub services: Vec<ServiceEntry>,
    /// Git configuration metadata (never credentials).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitConfig>,
    /// Associated projects.
    #[serde(default)]
    pub projects: Vec<ProjectEntry>,
}

/// Capture metadata: informational only, never affects convergence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// RFC 3339 capture timestamp (informational; not part of the reproducible
    /// content — two captures of an unchanged machine are semantically
    /// identical even when timestamps differ).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    /// Selection policy identifier for packages (e.g. `tooling-allowlist-v1`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_policy: Option<String>,
}

/// Platform the profile was captured on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub distro: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
}

/// Desired packages.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Packages {
    /// Sorted, unique apt package names.
    #[serde(default)]
    pub apt: Vec<String>,
}

/// One managed file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Portable machine target (`~/...`).
    pub target: String,
    /// Bundle-relative payload (`files/...`).
    pub source: String,
    /// Optional octal mode string (`"0644"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

/// A global literal environment value (non-secret only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged, deny_unknown_fields)]
pub enum EnvLiteral {
    /// Plain string literal.
    Value(String),
    /// Secret reference (value never stored).
    Secret {
        secret: String,
        #[serde(default)]
        required: bool,
    },
}

/// A user service intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServiceEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
}

/// Safe Git configuration metadata (never credential contents).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GitConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_helper: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excludes_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub aliases: std::collections::BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_gpgsign: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpg_format: Option<String>,
}

/// One associated project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProjectEntry {
    pub name: String,
    /// Portable path (`~/...` preferred; absolute accepted when traversal-free).
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcs: Option<String>,
    #[serde(default)]
    pub ecosystems: Vec<String>,
    /// Bundle-relative env schema (`env/<project>.toml`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_schema: Option<String>,
    /// Basenames of discovered `.env` files (metadata only).
    #[serde(default)]
    pub env_files: Vec<String>,
    /// Basenames of relevant config files (metadata only).
    #[serde(default)]
    pub config_files: Vec<String>,
}

/// Per-project environment schema (maps to `env/<project>.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvSchema {
    pub schema_version: u32,
    pub project: EnvProject,
    /// Sorted by name at generation time.
    pub variables: Vec<EnvVariable>,
}

/// The `[project]` table of an env schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvProject {
    pub name: String,
}

/// One expected variable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvVariable {
    pub name: String,
    /// `string` | `integer` | `boolean` | `enum`.
    #[serde(rename = "type")]
    pub var_type: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub required: bool,
    /// Allowed values (for `enum` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Secret manifest (maps to `secrets.manifest.toml`): metadata only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecretManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub secrets: Vec<SecretEntry>,
}

/// One secret reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecretEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Env filename the secret was discovered in (e.g. `.env`).
    pub source: String,
    /// `secret` | `likely_secret`.
    pub classification: String,
    /// Always `secret-service` in v1.
    pub backend: String,
    /// Deterministic `secret://` reference.
    #[serde(rename = "ref")]
    pub secret_ref: String,
    #[serde(default)]
    pub required: bool,
}

/// Optional resolved package versions (P0 §5; emitted by P2 capture as
/// `packages.lock.toml`: record-and-report, never enforced).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackagesLock {
    pub schema_version: u32,
    #[serde(default)]
    pub apt: std::collections::BTreeMap<String, String>,
}

impl Profile {
    /// Create a minimal new profile.
    pub fn new(name: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            name: name.to_string(),
            description: None,
            configctl_version: None,
            metadata: None,
            platform: None,
            packages: Packages::default(),
            files: Vec::new(),
            environment: None,
            services: Vec::new(),
            git: None,
            projects: Vec::new(),
        }
    }

    /// Canonicalize for determinism: sort every collection.
    pub fn canonicalize(&mut self) {
        self.packages.apt.sort();
        self.packages.apt.dedup();
        self.files.sort_by(|a, b| a.target.cmp(&b.target));
        self.services.sort_by(|a, b| a.name.cmp(&b.name));
        self.projects.sort_by(|a, b| a.path.cmp(&b.path));
        for p in &mut self.projects {
            p.ecosystems.sort();
            p.ecosystems.dedup();
            p.env_files.sort();
            p.env_files.dedup();
            p.config_files.sort();
            p.config_files.dedup();
        }
    }

    /// Validate the profile. Returns all errors (not just the first).
    pub fn validate(&self) -> Vec<String> {
        let mut errors: Vec<String> = Vec::new();

        if self.schema_version != SCHEMA_VERSION {
            errors.push(format!(
                "unsupported profile schema_version {} (this build supports {})",
                self.schema_version, SCHEMA_VERSION
            ));
        }
        if let Err(e) = paths::validate_profile_name(&self.name) {
            errors.push(e);
        }
        if let Some(d) = &self.description {
            if d.len() > 512 {
                errors.push("description exceeds 512 chars".into());
            }
            if d.contains('\0') {
                errors.push("description contains NUL".into());
            }
        }

        // Platform.
        if let Some(p) = &self.platform {
            if p.os != "linux" {
                errors.push(format!(
                    "unsupported platform os {:?}: v1 supports only `linux`",
                    p.os
                ));
            }
            if p.arch.is_empty() {
                errors.push("platform.arch must not be empty".into());
            } else if !matches!(
                p.arch.as_str(),
                "x86_64" | "aarch64" | "x86" | "arm" | "riscv64"
            ) {
                errors.push(format!("unsupported platform arch {:?}", p.arch));
            }
        }

        // Packages.
        {
            let mut seen = std::collections::BTreeSet::new();
            for name in &self.packages.apt {
                if let Err(e) = paths::validate_package_name(name) {
                    errors.push(e);
                }
                if !seen.insert(name.clone()) {
                    errors.push(format!("duplicate package entry: {name:?}"));
                }
            }
        }

        // Files.
        {
            let mut seen = std::collections::BTreeSet::new();
            for f in &self.files {
                if let Err(e) = paths::validate_file_target(&f.target) {
                    errors.push(e);
                }
                if let Err(e) = paths::validate_bundle_source(&f.source) {
                    errors.push(format!("file {:?}: {e}", f.target));
                }
                if let Some(m) = &f.mode {
                    if let Err(e) = paths::parse_mode(m) {
                        errors.push(format!("file {:?}: {e}", f.target));
                    }
                }
                if !seen.insert(f.target.clone()) {
                    errors.push(format!("duplicate file target: {:?}", f.target));
                }
            }
        }

        // Environment literals: names valid + no secret-like literals.
        if let Some(env) = &self.environment {
            for (k, v) in env {
                if let Err(e) = paths::validate_env_name(k) {
                    errors.push(e);
                }
                match v {
                    EnvLiteral::Value(lit) => {
                        if looks_secret_like(k, lit) {
                            errors.push(format!(
                                "environment.{k} looks like a secret; use `secret = \"secret://…\"` instead"
                            ));
                        }
                        if lit.contains('\0') {
                            errors.push(format!("environment.{k} contains NUL"));
                        }
                    }
                    EnvLiteral::Secret { secret, .. } => {
                        if let Err(e) = paths::validate_secret_ref(secret) {
                            errors.push(format!("environment.{k}: {e}"));
                        }
                    }
                }
            }
        }

        // Services.
        {
            let mut seen = std::collections::BTreeSet::new();
            for s in &self.services {
                if s.name.is_empty() || s.name.contains('\0') || s.name.contains("..") {
                    errors.push(format!("invalid service name: {:?}", s.name));
                } else if !s.name.ends_with(".service") {
                    errors.push(format!(
                        "unsupported service unit {:?}: v1 restricts to `.service` user units",
                        s.name
                    ));
                }
                if !seen.insert(s.name.clone()) {
                    errors.push(format!("duplicate service entry: {:?}", s.name));
                }
            }
        }

        // Git: emails/names must not contain NUL/newlines; helper is metadata.
        if let Some(g) = &self.git {
            for (label, v) in [
                ("git.user_name", g.user_name.as_deref()),
                ("git.user_email", g.user_email.as_deref()),
                ("git.credential_helper", g.credential_helper.as_deref()),
            ] {
                if let Some(s) = v {
                    if s.contains('\0') || s.contains('\n') || s.contains('\r') {
                        errors.push(format!("{label} contains control characters"));
                    }
                    if looks_secret_like(label, s) {
                        errors.push(format!(
                            "{label} looks secret-bearing; credential contents are never captured"
                        ));
                    }
                }
            }
            if let Some(e) = &g.user_email {
                if !e.is_empty() && !e.contains('@') && !e.contains('.') {
                    // Soft check only: emails should look plausible, but we do
                    // not reject unusual-but-valid values.
                }
            }
        }

        // Projects.
        {
            let mut seen_path = std::collections::BTreeSet::new();
            let mut seen_name = std::collections::BTreeSet::new();
            for p in &self.projects {
                if p.name.is_empty() || p.name.contains('\0') {
                    errors.push(format!("invalid project name: {:?}", p.name));
                }
                if let Err(e) = paths::validate_project_path(&p.path) {
                    errors.push(e);
                }
                if let Some(schema) = &p.env_schema {
                    if let Err(e) = paths::validate_env_schema_ref(schema) {
                        errors.push(format!("project {:?}: {e}", p.name));
                    }
                }
                if !seen_path.insert(p.path.clone()) {
                    errors.push(format!("duplicate project path: {:?}", p.path));
                }
                if !seen_name.insert(p.name.clone()) {
                    errors.push(format!("duplicate project name: {:?}", p.name));
                }
            }
        }

        errors
    }

    /// Serialize to a TOML string (deterministic: canonicalized clone).
    pub fn to_toml(&self) -> Result<String, String> {
        let mut clone = self.clone();
        clone.canonicalize();
        toml::to_string_pretty(&clone).map_err(|e| format!("profile serialize: {e}"))
    }

    /// Parse from a TOML string (unknown keys rejected via `deny_unknown_fields`).
    pub fn from_toml(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("profile parse: {e}"))
    }
}

impl EnvSchema {
    /// Validate an env schema. Returns all errors.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.schema_version != SCHEMA_VERSION {
            errors.push(format!(
                "unsupported env schema_version {} (this build supports {})",
                self.schema_version, SCHEMA_VERSION
            ));
        }
        if self.project.name.is_empty() || self.project.name.contains('\0') {
            errors.push(format!("invalid project name: {:?}", self.project.name));
        }
        let mut seen = std::collections::BTreeSet::new();
        for v in &self.variables {
            if let Err(e) = paths::validate_env_name(&v.name) {
                errors.push(e);
            }
            if !matches!(
                v.var_type.as_str(),
                "string" | "integer" | "boolean" | "enum"
            ) {
                errors.push(format!(
                    "variable {:?}: unsupported type {:?}",
                    v.name, v.var_type
                ));
            }
            if v.var_type == "enum" {
                match &v.values {
                    Some(vals) if !vals.is_empty() => {
                        let mut vs = std::collections::BTreeSet::new();
                        for val in vals {
                            if !vs.insert(val.clone()) {
                                errors.push(format!(
                                    "variable {:?}: duplicate enum value {val:?}",
                                    v.name
                                ));
                            }
                        }
                    }
                    _ => errors.push(format!(
                        "variable {:?}: type `enum` requires non-empty `values`",
                        v.name
                    )),
                }
            } else if v.values.is_some() {
                errors.push(format!(
                    "variable {:?}: `values` is only valid for type `enum`",
                    v.name
                ));
            }
            if !seen.insert(v.name.clone()) {
                errors.push(format!("duplicate variable: {:?}", v.name));
            }
        }
        errors
    }

    pub fn to_toml(&self) -> Result<String, String> {
        let mut clone = self.clone();
        clone.variables.sort_by(|a, b| a.name.cmp(&b.name));
        toml::to_string_pretty(&clone).map_err(|e| format!("env schema serialize: {e}"))
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("env schema parse: {e}"))
    }
}

impl SecretManifest {
    /// Validate the manifest. Returns all errors.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.schema_version != SCHEMA_VERSION {
            errors.push(format!(
                "unsupported secrets schema_version {} (this build supports {})",
                self.schema_version, SCHEMA_VERSION
            ));
        }
        let mut seen_ref = std::collections::BTreeSet::new();
        let mut seen_key = std::collections::BTreeSet::new();
        for s in &self.secrets {
            if let Err(e) = paths::validate_env_name(&s.name) {
                errors.push(e);
            }
            if !matches!(s.classification.as_str(), "secret" | "likely_secret") {
                errors.push(format!(
                    "secret {:?}: invalid classification {:?}",
                    s.name, s.classification
                ));
            }
            if s.backend != "secret-service" {
                errors.push(format!(
                    "secret {:?}: unsupported backend {:?} (v1 supports only `secret-service`)",
                    s.name, s.backend
                ));
            }
            if let Err(e) = paths::validate_secret_ref(&s.secret_ref) {
                errors.push(format!("secret {:?}: {e}", s.name));
            }
            if !seen_ref.insert(s.secret_ref.clone()) {
                errors.push(format!("duplicate secret ref: {:?}", s.secret_ref));
            }
            let key = format!("{}:{}", s.project.as_deref().unwrap_or(""), s.name);
            if !seen_key.insert(key.clone()) {
                errors.push(format!("duplicate secret declaration: {key:?}"));
            }
            if s.source.is_empty() || s.source.contains('\0') {
                errors.push(format!("secret {:?}: invalid source", s.name));
            }
        }
        errors
    }

    pub fn to_toml(&self) -> Result<String, String> {
        let mut clone = self.clone();
        clone
            .secrets
            .sort_by(|a, b| (&a.project, &a.name).cmp(&(&b.project, &b.name)));
        toml::to_string_pretty(&clone).map_err(|e| format!("secrets manifest serialize: {e}"))
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("secrets manifest parse: {e}"))
    }
}

impl PackagesLock {
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|e| format!("packages lock serialize: {e}"))
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("packages lock parse: {e}"))
    }
}

/// Heuristic: does a literal value look secret-bearing?
///
/// Conservative on purpose: known token prefixes, PEM blocks, JWT shapes, and
/// `password`/`secret` names with non-trivial values. Used only to *reject*
/// profiles that would otherwise persist secrets — never to extract values.
fn looks_secret_like(name: &str, value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return false;
    }
    if v.contains("BEGIN PRIVATE KEY")
        || v.contains("BEGIN RSA PRIVATE KEY")
        || v.contains("BEGIN OPENSSH PRIVATE KEY")
    {
        return true;
    }
    if v.starts_with("sk-")
        || v.starts_with("ghp_")
        || v.starts_with("gho_")
        || v.starts_with("github_pat_")
        || v.starts_with("xoxb-")
        || v.starts_with("xoxp-")
        || v.starts_with("sk_live_")
        || v.starts_with("sk_test_")
        || v.starts_with("AKIA")
        || v.starts_with("ASIA")
    {
        return true;
    }
    // JWT-like: three non-empty base64url segments (never an email address).
    if v.len() > 20
        && !v.contains(' ')
        && !v.contains('@')
        && v.chars().filter(|&c| c == '.').count() == 2
    {
        let segs: Vec<&str> = v.split('.').collect();
        if segs.len() == 3
            && segs.iter().all(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
            })
        {
            return true;
        }
    }
    // Name suggests secrecy and the value is non-trivial.
    let upper = name.to_uppercase();
    if (upper.contains("PASSWORD")
        || upper.contains("SECRET")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("PASSPHRASE"))
        && v.len() >= 4
    {
        return true;
    }
    false
}
