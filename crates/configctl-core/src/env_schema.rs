//! Environment schema + secret manifest generation (P2).
//!
//! For each discovered project `.env` family, capture generates a schema
//! (`env/<project>.toml`) that records *expectations* (names, types, secrecy,
//! requiredness) — never values. Secret-classified variables additionally
//! produce metadata-only entries in `secrets.manifest.toml`.
//!
//! Safe defaults: `type = "string"`, `secret = false`, `required = false`
//! unless stronger evidence exists:
//!
//! - `secret = true` when the variable name matches the P1 secret lexicon or
//!   any observed classification was `secret`/`likely_secret`;
//! - `required = true` when the variable appears in `.env.example` /
//!   `.env.sample` (the project's declared public schema);
//! - `type` is inferred conservatively from observed values held only in
//!   memory (integer/boolean/enum), otherwise `string`.
//!
//! `.env`, `.env.local`, `.env.production`, … contribute discovered names and
//! classifications, but their values are never copied.

use crate::profile::{EnvSchema, EnvVariable, SecretEntry, SecretManifest};
use std::collections::{BTreeMap, BTreeSet};

/// One observed variable occurrence (value held only in memory for type
/// inference; never persisted).
#[derive(Debug, Clone)]
pub struct ObservedVar {
    pub name: String,
    pub classification: String,
    pub from_example: bool,
    /// Raw value for in-memory type inference (never serialized).
    pub value: Option<String>,
}

/// Build an [`EnvSchema`] for one project from its observed variables.
///
/// `observations` may contain duplicates (same var in several files); they
/// are merged deterministically. `profile_name` is used only to build
/// nothing here (refs live in the manifest), but accepted for symmetry.
pub fn build_env_schema(project: &str, observations: &[ObservedVar]) -> EnvSchema {
    // Merge by name: secret if ANY occurrence is secret-like; required if ANY
    // occurrence came from an example file; values collected for inference.
    let mut by_name: BTreeMap<String, Vec<&ObservedVar>> = BTreeMap::new();
    for o in observations {
        by_name.entry(o.name.clone()).or_default().push(o);
    }
    let mut variables: Vec<EnvVariable> = Vec::new();
    for (name, occs) in &by_name {
        let secret =
            occs.iter().any(|o| is_secret_like(&o.classification)) || secret_name_hint(name);
        let required = occs.iter().any(|o| o.from_example);
        let values: Vec<String> = occs
            .iter()
            .filter_map(|o| o.value.clone())
            .filter(|v| !v.is_empty())
            .collect();
        let (var_type, enum_values) = infer_type(name, &values);
        variables.push(EnvVariable {
            name: name.clone(),
            var_type,
            secret,
            required,
            values: enum_values,
            description: None,
        });
    }
    variables.sort_by(|a, b| a.name.cmp(&b.name));
    EnvSchema {
        schema_version: crate::profile::SCHEMA_VERSION,
        project: crate::profile::EnvProject {
            name: project.to_string(),
        },
        variables,
    }
}

/// Build a [`SecretManifest`] from per-project observations.
///
/// Deduplication rule (deterministic): keyed by `(project, name)`; when the
/// same logical secret appears in several files, the smallest source filename
/// (lexicographically) is recorded as `source`. Classification is the
/// strongest observed (`secret` beats `likely_secret`).
pub fn build_secret_manifest(
    profile_name: &str,
    per_project: &BTreeMap<String, Vec<ObservedVarWithSource>>,
) -> SecretManifest {
    #[derive(Debug, Clone)]
    struct Acc {
        source: BTreeSet<String>,
        classification: String,
        required: bool,
    }
    let mut acc: BTreeMap<(String, String), Acc> = BTreeMap::new();
    for (project, vars) in per_project {
        for v in vars {
            if !is_secret_like(&v.classification) {
                continue;
            }
            let key = (project.clone(), v.name.clone());
            let e = acc.entry(key).or_insert(Acc {
                source: BTreeSet::new(),
                classification: "likely_secret".into(),
                required: false,
            });
            e.source.insert(v.source.clone());
            if v.classification == "secret" {
                e.classification = "secret".into();
            }
            if v.from_example {
                e.required = true;
            }
        }
    }
    let mut secrets: Vec<SecretEntry> = Vec::new();
    for ((project, name), a) in acc {
        let source = a
            .source
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| ".env".into());
        let secret_ref = format!("secret://{profile_name}/{project}/{name}");
        secrets.push(SecretEntry {
            name: name.clone(),
            project: Some(project.clone()),
            source,
            classification: a.classification,
            backend: "secret-service".into(),
            secret_ref,
            required: a.required,
        });
    }
    secrets.sort_by(|a, b| (&a.project, &a.name).cmp(&(&b.project, &b.name)));
    SecretManifest {
        schema_version: crate::profile::SCHEMA_VERSION,
        secrets,
    }
}

/// One observed variable plus the env filename it came from.
#[derive(Debug, Clone)]
pub struct ObservedVarWithSource {
    pub name: String,
    pub classification: String,
    pub source: String,
    pub from_example: bool,
}

fn is_secret_like(classification: &str) -> bool {
    matches!(classification, "secret" | "likely_secret")
}

/// Name-based evidence for `secret = true` (P1 lexicon subset, deterministic).
fn secret_name_hint(name: &str) -> bool {
    let upper = name.to_uppercase();
    const NEEDLES: &[&str] = &[
        "API_KEY",
        "APIKEY",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "TOKEN",
        "PRIVATE_KEY",
        "CLIENT_SECRET",
        "CREDENTIAL",
        "DATABASE_URL",
        "DB_PASSWORD",
        "AWS_SECRET",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "HF_TOKEN",
        "HUGGINGFACE_TOKEN",
        "SLACK_TOKEN",
        "STRIPE",
    ];
    NEEDLES.iter().any(|n| upper.contains(n))
}

/// Conservative type inference from in-memory values.
///
/// - `enum` only for well-known enumerated vars (`NODE_ENV`, `APP_ENV`) with
///   values drawn from a fixed set;
/// - `integer` when every non-empty value parses as `i64`;
/// - `boolean` when every non-empty value is boolean-like;
/// - otherwise `string` (safe default; never invents semantics).
fn infer_type(name: &str, values: &[String]) -> (String, Option<Vec<String>>) {
    let non_empty: Vec<&str> = values
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    // NODE_ENV-style enums.
    if matches!(name, "NODE_ENV" | "APP_ENV" | "ENVIRONMENT") && !non_empty.is_empty() {
        const ALLOWED: &[&str] = &["development", "test", "production"];
        if non_empty.iter().all(|v| ALLOWED.contains(v)) {
            let mut vals: Vec<String> = ALLOWED.iter().map(|s| s.to_string()).collect();
            vals.sort();
            vals.dedup();
            return ("enum".into(), Some(vals));
        }
        return ("string".into(), None);
    }
    if non_empty.is_empty() {
        return ("string".into(), None);
    }
    if non_empty.iter().all(|v| v.parse::<i64>().is_ok()) {
        return ("integer".into(), None);
    }
    if non_empty.iter().all(|v| {
        matches!(
            v.to_lowercase().as_str(),
            "true" | "false" | "0" | "1" | "yes" | "no" | "on" | "off"
        )
    }) {
        return ("boolean".into(), None);
    }
    ("string".into(), None)
}
