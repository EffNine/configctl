//! `configctl secrets list|set|get|import`.
//!
//! Safety contract:
//! - Values enter only via hidden prompt or `--stdin` (never argv).
//! - `get` shows metadata by default; `--show` prints the value and requires
//!   a TTY unless `--force` is also given (with a stderr warning).
//! - Plaintext values never appear in `--json`, logs, or errors.
//! - Without a supported backend (and without the explicit test dir), every
//!   command fails closed with exit 6. There is no plaintext fallback.

use configctl_core::command::CommandRunner;
use configctl_core::profile_load;
use configctl_core::secrets::{self, SecretError, SecretStore, SecretToolBackend};
use std::io::{IsTerminal, Read};
use std::path::Path;

/// Resolve the active secret store: test-dir backend when explicitly opted in
/// (`CONFIGCTL_SECRET_TEST_DIR`), otherwise the Linux Secret Service backend.
/// Returns `None` with an exit-6 message when the Secret Service is missing.
pub fn resolve_store<'a>(
    runner: &'a dyn CommandRunner,
) -> Result<Box<dyn SecretStore + 'a>, String> {
    if let Some(test) = configctl_core::secrets::FileTestBackend::from_env() {
        return Ok(Box::new(test));
    }
    // Probe availability through the backend itself on first use; here we
    // only check the `secret-tool` binary exists via PATH lookup.
    if which_secret_tool().is_none() {
        return Err("no supported secret backend is available (install libsecret / secret-tool and unlock your keyring)".into());
    }
    Ok(Box::new(SecretToolBackend { runner }))
}

fn which_secret_tool() -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("secret-tool"))
            .find(|p| p.is_file())
    })
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

pub struct SecretListEntry {
    pub project: String,
    pub name: String,
    pub secret_ref: String,
    pub status: String,
}

pub struct SecretListOutput {
    pub entries: Vec<SecretListEntry>,
    pub error: Option<String>,
    pub exit_code: i32,
}

/// List secret references from a profile manifest with backend status.
/// Never values.
pub fn run_list(
    profile_arg: Option<&str>,
    project_filter: Option<&str>,
    runner: &dyn CommandRunner,
) -> SecretListOutput {
    let profile_dir = match super::common::resolve_profile_default(profile_arg) {
        Ok(d) => d,
        Err(e) => {
            return SecretListOutput {
                entries: Vec::new(),
                error: Some(e),
                exit_code: 2,
            };
        }
    };
    let loaded = match profile_load::load_profile_dir(&profile_dir) {
        Ok(l) => l,
        Err(e) => {
            return SecretListOutput {
                entries: Vec::new(),
                error: Some(e),
                exit_code: 2,
            };
        }
    };
    let Some(manifest) = loaded.manifest else {
        return SecretListOutput {
            entries: Vec::new(),
            error: None,
            exit_code: 0,
        };
    };
    // Backend may be unavailable: statuses become `backend_error` (exit 6 only
    // when the backend itself is required; list degrades to manifest view).
    let store = resolve_store(runner);
    let mut entries = Vec::new();
    for s in &manifest.secrets {
        let project = s.project.clone().unwrap_or_default();
        if let Some(f) = project_filter {
            if project != f {
                continue;
            }
        }
        let status = match &store {
            Ok(st) => match st.exists(&s.secret_ref) {
                Some(true) => "present",
                Some(false) => "missing",
                None => "backend_error",
            },
            Err(_) => "backend_error",
        };
        entries.push(SecretListEntry {
            project,
            name: s.name.clone(),
            secret_ref: s.secret_ref.clone(),
            status: status.into(),
        });
    }
    entries.sort_by(|a, b| (&a.project, &a.name).cmp(&(&b.project, &b.name)));
    SecretListOutput {
        entries,
        error: None,
        exit_code: 0,
    }
}

pub fn render_list_human(out: &SecretListOutput) -> String {
    if out.entries.is_empty() {
        return "No secret references.\n".into();
    }
    let mut s = String::from("project\t\tname\t\tref\t\tstatus\n\n");
    for e in &out.entries {
        s.push_str(&format!(
            "{}\t\t{}\t\t{}\t\t{}\n",
            e.project, e.name, e.secret_ref, e.status
        ));
    }
    s.push_str(
        "\nValues are never shown. Use `secrets get <ref> --show` for explicit retrieval.\n",
    );
    s
}

// ---------------------------------------------------------------------------
// set
// ---------------------------------------------------------------------------

pub struct SecretSetOutput {
    pub secret_ref: String,
    pub error: Option<String>,
    pub exit_code: i32,
}

/// Read a value from `--stdin` or a hidden prompt, then store it.
/// `argv_value` is always rejected (argv is world-readable in `/proc`).
pub fn run_set(
    secret_ref: &str,
    stdin_mode: bool,
    argv_value: Option<&str>,
    _runner: &dyn CommandRunner,
) -> SecretSetOutput {
    if argv_value.is_some() {
        return SecretSetOutput {
            secret_ref: secret_ref.into(),
            error: Some("refusing to accept a secret value as a command-line argument (argv is visible in /proc); use --stdin or the interactive prompt".into()),
            exit_code: 2,
        };
    }
    if let Err(e) = configctl_core::paths::validate_secret_ref(secret_ref) {
        return SecretSetOutput {
            secret_ref: secret_ref.into(),
            error: Some(e),
            exit_code: 2,
        };
    }
    // Read the value first (so prompt failures don't touch the backend).
    let value: Vec<u8> = if stdin_mode {
        let mut buf = Vec::new();
        match std::io::stdin().read_to_end(&mut buf) {
            Ok(_) => buf,
            Err(_) => {
                return SecretSetOutput {
                    secret_ref: secret_ref.into(),
                    error: Some("failed to read secret from stdin".into()),
                    exit_code: 1,
                };
            }
        }
    } else {
        if !std::io::stdin().is_terminal() {
            return SecretSetOutput {
                secret_ref: secret_ref.into(),
                error: Some("no TTY for hidden prompt; re-run with --stdin".into()),
                exit_code: 2,
            };
        }
        match rpassword::prompt_password(format!("Value for {secret_ref}: ")) {
            Ok(p) => p.into_bytes(),
            Err(_) => {
                return SecretSetOutput {
                    secret_ref: secret_ref.into(),
                    error: Some("failed to read hidden input".into()),
                    exit_code: 1,
                };
            }
        }
    };
    // Strip one trailing newline (stdin convention), keep everything else exact.
    let value = strip_single_trailing_newline(value);
    if value.is_empty() {
        return SecretSetOutput {
            secret_ref: secret_ref.into(),
            error: Some("refusing to store an empty secret".into()),
            exit_code: 2,
        };
    }
    let secret = secrets::SecretValue::new(value);
    // Test backend path.
    if let Some(test) = configctl_core::secrets::FileTestBackend::from_env() {
        return match test.set(secret_ref, &secret) {
            Ok(()) => SecretSetOutput {
                secret_ref: secret_ref.into(),
                error: None,
                exit_code: 0,
            },
            Err(e) => SecretSetOutput {
                secret_ref: secret_ref.into(),
                error: Some(secret_error_message(&e)),
                exit_code: secret_exit_code(&e),
            },
        };
    }
    // Production path: secret-tool with piped stdin (fixed argv, no shell).
    match secrets::cli_secret_tool_store(secret_ref, &secret) {
        Ok(()) => SecretSetOutput {
            secret_ref: secret_ref.into(),
            error: None,
            exit_code: 0,
        },
        Err(e) => SecretSetOutput {
            secret_ref: secret_ref.into(),
            error: Some(secret_error_message(&e)),
            exit_code: secret_exit_code(&e),
        },
    }
}

fn strip_single_trailing_newline(mut v: Vec<u8>) -> Vec<u8> {
    if v.last() == Some(&b'\n') {
        v.pop();
        if v.last() == Some(&b'\r') {
            v.pop();
        }
    }
    v
}

// ---------------------------------------------------------------------------
// get
// ---------------------------------------------------------------------------

pub struct SecretGetOutput {
    pub secret_ref: String,
    /// Present only when `--show` was explicitly authorized.
    pub value: Option<secrets::SecretValue>,
    pub status: String,
    pub error: Option<String>,
    pub exit_code: i32,
}

/// Metadata by default; `--show` prints the value (TTY or `--force`, with a
/// stderr warning). `--show --json` is refused (exit 2): plaintext never
/// enters machine-readable output.
#[allow(clippy::too_many_arguments)]
pub fn run_get(
    secret_ref: &str,
    show: bool,
    force: bool,
    json: bool,
    runner: &dyn CommandRunner,
) -> SecretGetOutput {
    if let Err(e) = configctl_core::paths::validate_secret_ref(secret_ref) {
        return SecretGetOutput {
            secret_ref: secret_ref.into(),
            value: None,
            status: "invalid".into(),
            error: Some(e),
            exit_code: 2,
        };
    }
    if show && json {
        return SecretGetOutput {
            secret_ref: secret_ref.into(),
            value: None,
            status: "refused".into(),
            error: Some("refusing to emit a secret value in --json output".into()),
            exit_code: 2,
        };
    }
    let store = match resolve_store(runner) {
        Ok(s) => s,
        Err(e) => {
            return SecretGetOutput {
                secret_ref: secret_ref.into(),
                value: None,
                status: "backend_unavailable".into(),
                error: Some(e),
                exit_code: 6,
            };
        }
    };
    if !show {
        let status = match store.exists(secret_ref) {
            Some(true) => "present",
            Some(false) => "missing",
            None => "backend_error",
        };
        return SecretGetOutput {
            secret_ref: secret_ref.into(),
            value: None,
            status: status.into(),
            error: None,
            exit_code: 0,
        };
    }
    // Explicit retrieval.
    if !std::io::stdout().is_terminal() && !force {
        return SecretGetOutput {
            secret_ref: secret_ref.into(),
            value: None,
            status: "refused".into(),
            error: Some("stdout is not a TTY; re-run with --force to print anyway (the value will be visible to any redirect)".into()),
            exit_code: 2,
        };
    }
    match store.get(secret_ref) {
        Ok(v) => {
            eprintln!("warning: displaying a secret value (not logged)");
            SecretGetOutput {
                secret_ref: secret_ref.into(),
                value: Some(v),
                status: "present".into(),
                error: None,
                exit_code: 0,
            }
        }
        Err(SecretError::NotFound) => SecretGetOutput {
            secret_ref: secret_ref.into(),
            value: None,
            status: "missing".into(),
            error: Some(format!("secret not found: {secret_ref}")),
            exit_code: 3,
        },
        Err(e) => SecretGetOutput {
            secret_ref: secret_ref.into(),
            value: None,
            status: "backend_error".into(),
            error: Some(secret_error_message(&e)),
            exit_code: secret_exit_code(&e),
        },
    }
}

// ---------------------------------------------------------------------------
// import
// ---------------------------------------------------------------------------

/// One import candidate (names only — never values).
#[derive(Debug, Clone)]
pub struct ImportCandidate {
    pub file: String,
    pub name: String,
    pub classification: String,
    pub signals: Vec<String>,
}

pub struct SecretImportOutput {
    pub candidates: Vec<ImportCandidate>,
    pub imported: Vec<String>,
    pub ignored: Vec<String>,
    pub error: Option<String>,
    pub exit_code: i32,
    pub dry_run: bool,
}

/// Parse `.env` files locally, classify, and store selected values.
///
/// - `--dry-run`: list candidates, import nothing, prompt nothing.
/// - Interactive TTY: per-item review (import/ignore/quit).
/// - `--yes` (non-interactive): imports only high-confidence `secret`
///   classifications; `likely_secret` requires explicit review.
/// - Never rewrites the source file; never keeps plaintext copies.
pub fn run_import(
    paths: &[String],
    dry_run: bool,
    yes: bool,
    home_fallback: Option<&Path>,
    _runner: &dyn CommandRunner,
) -> SecretImportOutput {
    // Resolve target files: explicit paths, or `~/.env`-style home fallback.
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for p in paths {
        let pb = if p == "~" {
            home_fallback
                .map(|h| h.to_path_buf())
                .unwrap_or_else(|| Path::new(p).to_path_buf())
        } else if let Some(rest) = p.strip_prefix("~/") {
            match home_fallback {
                Some(h) => h.join(rest),
                None => Path::new(p).to_path_buf(),
            }
        } else {
            Path::new(p).to_path_buf()
        };
        files.push(pb);
    }
    if files.is_empty() {
        return SecretImportOutput {
            candidates: Vec::new(),
            imported: Vec::new(),
            ignored: Vec::new(),
            error: Some("no import paths given".into()),
            exit_code: 2,
            dry_run,
        };
    }
    // Parse + classify (bounded, in-memory).
    let scorer = configctl_discovery::secret::EntropyScorer::default();
    let mut candidates: Vec<ImportCandidate> = Vec::new();
    for f in &files {
        let meta = match std::fs::symlink_metadata(f) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let Ok(parsed) = configctl_core::envfile::parse_file(
            f,
            &configctl_core::envfile::ParseLimits {
                max_bytes: 256 * 1024,
                max_variables: 10_000,
            },
        ) else {
            continue;
        };
        for v in &parsed.variables {
            let stem = f
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let res = configctl_discovery::secret::classify_variable(v, &stem, &scorer);
            if res.is_secret_like() {
                candidates.push(ImportCandidate {
                    file: f.to_string_lossy().into_owned(),
                    name: v.name.clone(),
                    classification: res.classification.as_str().into(),
                    signals: res.signals.clone(),
                });
            }
        }
    }
    candidates.sort_by(|a, b| (&a.file, &a.name).cmp(&(&b.file, &b.name)));
    candidates.dedup_by(|a, b| a.file == b.file && a.name == b.name);
    if dry_run {
        return SecretImportOutput {
            candidates,
            imported: Vec::new(),
            ignored: Vec::new(),
            error: None,
            exit_code: 0,
            dry_run: true,
        };
    }
    // Backend required for any real import.
    if configctl_core::secrets::FileTestBackend::from_env().is_none()
        && which_secret_tool().is_none()
    {
        return SecretImportOutput {
            candidates,
            imported: Vec::new(),
            ignored: Vec::new(),
            error: Some("no supported secret backend is available (install libsecret / secret-tool and unlock your keyring)".into()),
            exit_code: 6,
            dry_run: false,
        };
    }
    let interactive = std::io::stdin().is_terminal() && !yes;
    let mut imported = Vec::new();
    let mut ignored = Vec::new();
    for c in &candidates {
        let decision = if interactive {
            prompt_import(c)
        } else if c.classification == "secret" {
            ImportDecision::Import
        } else {
            ImportDecision::Ignore
        };
        match decision {
            ImportDecision::Quit => break,
            ImportDecision::Ignore => {
                ignored.push(c.name.clone());
            }
            ImportDecision::Import => {
                // Re-read the value from the source file (bounded, in-memory
                // only), store it, then drop it. The source file is never
                // modified; no temp plaintext copy is ever written.
                match read_single_value(&c.file, &c.name) {
                    Some(value) => {
                        let secret = secrets::SecretValue::new(value);
                        let stored = if let Some(test) =
                            configctl_core::secrets::FileTestBackend::from_env()
                        {
                            let secret_ref = format!("secret://import/{}", c.name);
                            test.set(&secret_ref, &secret).is_ok()
                        } else {
                            let secret_ref = format!("secret://import/{}", c.name);
                            secrets::cli_secret_tool_store(&secret_ref, &secret).is_ok()
                        };
                        if stored {
                            imported.push(c.name.clone());
                        }
                    }
                    None => ignored.push(c.name.clone()),
                }
            }
        }
    }
    SecretImportOutput {
        candidates,
        imported,
        ignored,
        error: None,
        exit_code: 0,
        dry_run: false,
    }
}

enum ImportDecision {
    Import,
    Ignore,
    Quit,
}

fn prompt_import(c: &ImportCandidate) -> ImportDecision {
    eprintln!(
        "{} — {} [{}] ({})",
        c.file,
        c.name,
        c.classification,
        c.signals.join(", ")
    );
    eprintln!("  [i]mport  [k]ignore  [q]uit");
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(_) => match line.trim().to_lowercase().as_str() {
            "i" | "import" => ImportDecision::Import,
            "q" | "quit" => ImportDecision::Quit,
            _ => ImportDecision::Ignore,
        },
        Err(_) => ImportDecision::Ignore,
    }
}

/// Re-read one value from a file (bounded). Returns raw bytes (caller stores
/// them immediately and drops them; never logged).
fn read_single_value(file: &str, name: &str) -> Option<Vec<u8>> {
    let parsed = configctl_core::envfile::parse_file(
        Path::new(file),
        &configctl_core::envfile::ParseLimits {
            max_bytes: 256 * 1024,
            max_variables: 10_000,
        },
    )
    .ok()?;
    for v in &parsed.variables {
        if v.name == name {
            return v.with_value(|val| Some(val.as_bytes().to_vec()));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// shared
// ---------------------------------------------------------------------------

/// Map a backend error to a message (never values) + exit code.
pub fn secret_error_message(e: &SecretError) -> String {
    match e {
        SecretError::Unavailable(m) => m.clone(),
        SecretError::NotFound => "secret not found".into(),
        SecretError::InvalidRef(m) => m.clone(),
        SecretError::Backend(m) => m.clone(),
    }
}

pub fn secret_exit_code(e: &SecretError) -> i32 {
    match e {
        SecretError::Unavailable(_) => 6,
        SecretError::NotFound => 3,
        SecretError::InvalidRef(_) => 2,
        SecretError::Backend(_) => 1,
    }
}
