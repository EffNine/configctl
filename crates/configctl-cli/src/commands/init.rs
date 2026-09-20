//! `configctl init` — create config, profiles, and state directories.
//!
//! Touches nothing else. `--force` overwrites an existing config file.

use std::path::PathBuf;

/// Result of init.
pub struct InitOutput {
    pub config_path: PathBuf,
    pub profiles_dir: PathBuf,
    pub state_dir: PathBuf,
    pub created_config: bool,
    pub error: Option<String>,
    pub exit_code: i32,
}

fn config_home() -> PathBuf {
    if let Some(c) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(c)
    } else if let Some(h) = std::env::var_os("HOME") {
        PathBuf::from(h).join(".config")
    } else {
        PathBuf::from(".config")
    }
}

/// Run init.
pub fn run_init(
    profile_name: Option<&str>,
    force: bool,
    config_override: Option<&str>,
    state_dir_override: Option<&str>,
) -> InitOutput {
    let base = config_home().join("configctl");
    let config_path = match config_override {
        Some(c) => PathBuf::from(c),
        None => base.join("config.toml"),
    };
    let profiles_dir = match config_override {
        Some(_) => config_path
            .parent()
            .map(|p| p.join("profiles"))
            .unwrap_or_else(|| base.join("profiles")),
        None => base.join("profiles"),
    };
    let state_dir = configctl_core::state::resolve_state_dir(state_dir_override);
    if let Some(name) = profile_name {
        if let Err(e) = configctl_core::paths::validate_profile_name(name) {
            return InitOutput {
                config_path,
                profiles_dir,
                state_dir,
                created_config: false,
                error: Some(e),
                exit_code: 2,
            };
        }
    }
    if let Some(parent) = config_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return InitOutput {
                config_path,
                profiles_dir,
                state_dir,
                created_config: false,
                error: Some(format!("create config dir: {e:?}")),
                exit_code: 1,
            };
        }
    }
    if let Err(e) = std::fs::create_dir_all(&profiles_dir) {
        return InitOutput {
            config_path,
            profiles_dir,
            state_dir,
            created_config: false,
            error: Some(format!("create profiles dir: {e:?}")),
            exit_code: 1,
        };
    }
    if let Err(e) = configctl_core::state::ensure_state_dir(&state_dir) {
        return InitOutput {
            config_path,
            profiles_dir,
            state_dir,
            created_config: false,
            error: Some(e),
            exit_code: 1,
        };
    }
    let default_profile = profile_name.unwrap_or("work");
    let content = format!(
        "schema_version = 1\ndefault_profile = \"{default_profile}\"\n\n[scan]\nmax_file_bytes = 262144\nmax_findings = 10000\n\n[secrets]\nprovider = \"secret-service\"\n\n[state]\n# directory = \"~/.local/state/configctl\"\n"
    );
    if config_path.exists() && !force {
        let msg = format!(
            "{} already exists (refusing to overwrite; use --force)",
            config_path.display()
        );
        return InitOutput {
            config_path,
            profiles_dir,
            state_dir,
            created_config: false,
            error: Some(msg),
            exit_code: 2,
        };
    }
    match std::fs::write(&config_path, content.as_bytes()) {
        Ok(()) => InitOutput {
            config_path,
            profiles_dir,
            state_dir,
            created_config: true,
            error: None,
            exit_code: 0,
        },
        Err(e) => InitOutput {
            config_path,
            profiles_dir,
            state_dir,
            created_config: false,
            error: Some(format!("write config: {e:?}")),
            exit_code: 1,
        },
    }
}

/// Render human output.
pub fn render_human(out: &InitOutput) -> String {
    format!(
        "Created  {}\nCreated  {}\nCreated  {}\n",
        out.config_path.display(),
        out.profiles_dir.display(),
        out.state_dir.display()
    )
}
