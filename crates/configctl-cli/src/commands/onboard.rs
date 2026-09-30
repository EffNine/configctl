//! `configctl onboard` — guided first run (v1.2, phase E4).
//!
//! Composes the existing read-only steps into one walkthrough: a scan, an
//! environment explanation, and a capture summary. It is read-only apart from
//! writing the profile bundle — it never plans, applies, or changes the
//! machine's configuration, and it never guesses an answer for the user.

use configctl_core::command::CommandRunner;
use std::path::{Path, PathBuf};

/// Result of `onboard`.
pub struct OnboardOutput {
    pub text: String,
    pub data: serde_json::Value,
    pub error: Option<String>,
    pub exit_code: i32,
}

fn fail(msg: &str, exit_code: i32) -> OnboardOutput {
    OnboardOutput {
        text: String::new(),
        data: serde_json::json!({}),
        error: Some(msg.to_string()),
        exit_code,
    }
}

/// True when the directory exists and already holds anything.
fn non_empty_dir(p: &Path) -> bool {
    std::fs::read_dir(p)
        .map(|mut it| it.next().is_some())
        .unwrap_or(false)
}

/// Run the guided first pass.
///
/// `roots` are the paths to look at (defaults to the usual project roots under
/// `$HOME`); the profile bundle is written to `output` (default
/// `~/.config/configctl/profiles/this-machine`). An existing non-empty output
/// directory is refused unless `force` is set.
#[allow(clippy::too_many_arguments)]
pub fn run_onboard(
    roots: &[String],
    extra_roots: &[String],
    output: Option<&str>,
    home_override: Option<&Path>,
    force: bool,
    runner: &dyn CommandRunner,
) -> OnboardOutput {
    let home: PathBuf = match home_override {
        Some(h) => h.to_path_buf(),
        None => match dirs::home_dir() {
            Some(h) => h,
            None => return fail("cannot determine $HOME", 2),
        },
    };
    let out_dir: PathBuf = match output {
        Some(o) => PathBuf::from(o),
        None => home.join(".config/configctl/profiles/this-machine"),
    };

    if non_empty_dir(&out_dir) && !force {
        return fail(
            &format!(
                "{} already exists and is not empty; pass --output DIR or --force to overwrite",
                out_dir.display()
            ),
            5,
        );
    }

    let mut text = String::new();
    text.push_str("configctl onboard — nothing is changed until you ask for it.\n\n");

    // ---- Step 1/4: look around (read-only) ----
    text.push_str("Step 1/4  Looking around (read-only scan)…\n");
    let scan =
        crate::commands::scan::run_scan(roots, extra_roots, None, false, false, false, runner);
    if let Some(err) = &scan.error_envelope {
        let message = err
            .errors
            .first()
            .map(|w| w.message.clone())
            .unwrap_or_else(|| "scan failed".into());
        return fail(&message, 2);
    }
    let r = &scan.result;
    text.push_str(&format!(
        "          {} project(s), {} environment file(s), {} config file(s)\n\n",
        r.projects.len(),
        r.env_files.len(),
        r.config_files.len()
    ));

    // ---- Step 2/4: understand the shell environment (read-only) ----
    text.push_str("Step 2/4  Understanding your shell settings (read-only)…\n");
    let explain = crate::commands::env::run_env_explain(Some(&home));
    if let Some(e) = &explain.error {
        return fail(e, explain.exit_code);
    }
    let sources = explain.data["sources"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let conflicts = explain.data["conflicts"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let secret_names = explain.data["secret_names"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    text.push_str(&format!(
        "          {} shell startup file(s); {} setting(s) could be managed; {} look like secrets\n",
        sources.len(),
        explain.data["managed_count"].as_u64().unwrap_or(0),
        secret_names.len()
    ));
    if !conflicts.is_empty() {
        text.push_str(&format!(
            "          {} conflicting setting(s): {}\n",
            conflicts.len(),
            conflicts
                .iter()
                .filter_map(|c| c["name"].as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    text.push('\n');

    // ---- Step 3/4: capture (writes only the profile bundle) ----
    text.push_str("Step 3/4  Writing your profile bundle…\n");
    let out_str = out_dir.to_string_lossy().into_owned();
    let captured = crate::commands::capture::run_capture(
        None,
        roots,
        extra_roots,
        Some(&out_str),
        force,
        None,
        false,
        Some("first-run profile written by `configctl onboard`"),
        runner,
    );
    if let Some(err) = &captured.error_envelope {
        let message = err
            .errors
            .first()
            .map(|w| w.message.clone())
            .unwrap_or_else(|| "capture failed".into());
        return fail(&message, 2);
    }
    let summary = captured
        .result
        .as_ref()
        .map(|c| c.summary.clone())
        .unwrap_or_default();
    text.push_str(&format!(
        "          {} project(s), {} file(s), {} package(s), {} secret reference(s)\n\n",
        summary.projects, summary.files, summary.packages, summary.secrets
    ));

    // ---- Step 4/4: what to do next (no action taken) ----
    text.push_str(&format!(
        "Step 4/4  Your profile is ready: {}\n\
         \n\
         Review the exact changes:  configctl plan {}\n\
         Apply them (approved, journaled, backed up):  configctl apply --last\n\
         Undo anything:  configctl rollback --last\n\
         \n\
         Nothing has been changed yet. `onboard` only wrote the profile bundle.\n\
         To preview one managed shell env file:  configctl env consolidate --dry-run {}\n",
        out_dir.display(),
        out_dir.display(),
        out_dir.display()
    ));

    let data = serde_json::json!({
        "profile_dir": out_dir.to_string_lossy(),
        "projects": r.projects.len(),
        "env_files": r.env_files.len(),
        "config_files": r.config_files.len(),
        "shell_sources": sources.len(),
        "managed_settings": explain.data["managed_count"],
        "secret_settings": secret_names.len(),
        "conflicts": conflicts.iter().filter_map(|c| c["name"].as_str()).collect::<Vec<_>>(),
        "capture": {
            "projects": summary.projects,
            "files": summary.files,
            "packages": summary.packages,
            "secrets": summary.secrets,
        },
        "changed": false,
    });

    OnboardOutput {
        text,
        data,
        error: None,
        exit_code: 0,
    }
}
