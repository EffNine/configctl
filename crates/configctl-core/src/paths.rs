//! Portable path rules for P2 profiles.
//!
//! Profiles use portable logical paths (`~/...`) for machine targets and
//! bundle-relative paths (`files/...`, `env/...`) for payload references.
//! This module is pure (no I/O) so it is easy to unit-test.

/// True when `s` contains a NUL byte.
pub fn has_nul(s: &str) -> bool {
    s.contains('\0')
}

/// Split a path string into components for traversal checks.
///
/// Handles both `/` and (defensively) `\` separators; empty components from
/// duplicate slashes are ignored.
fn components(s: &str) -> Vec<&str> {
    s.split(['/', '\\']).filter(|c| !c.is_empty()).collect()
}

/// True when any component is exactly `..`.
pub fn has_dotdot(s: &str) -> bool {
    components(s).contains(&"..")
}

/// Validate a machine target path for `[[files]]`.
///
/// Rules (P0 §2.3 + P2 §14):
/// - must start with `~/`
/// - must not contain `..` components or NUL bytes
/// - must have a non-empty remainder after `~/`
/// - must not contain shell metacharacters that would be unsafe to render
///   (`;`, backtick, `$()`, `|`, `&` are rejected; the target is data, never
///   executed, but rejecting keeps profiles honest)
pub fn validate_file_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("file target must not be empty".into());
    }
    if has_nul(target) {
        return Err(format!("file target contains NUL: {target:?}"));
    }
    if !target.starts_with("~/") {
        return Err(format!(
            "file target must start with `~/` (got {target:?}); absolute paths outside $HOME are rejected in v1"
        ));
    }
    let rest = &target[2..];
    if rest.is_empty() {
        return Err("file target `~/` has no remainder".into());
    }
    if has_dotdot(target) {
        return Err(format!("file target contains `..`: {target:?}"));
    }
    for bad in [";", "`", "$(", "|", "&", "\n", "\r"] {
        if target.contains(bad) {
            return Err(format!(
                "file target contains unsafe sequence {bad:?}: {target:?}"
            ));
        }
    }
    Ok(())
}

/// Validate a bundle-relative source path (`files/...`, `env/...`).
///
/// Rules (P0 §1 + P2 §14):
/// - must be relative (no leading `/`, no `~/`, no Windows drive)
/// - must not contain `..` or NUL
/// - must be non-empty
pub fn validate_bundle_source(source: &str) -> Result<(), String> {
    if source.is_empty() {
        return Err("bundle source must not be empty".into());
    }
    if has_nul(source) {
        return Err(format!("bundle source contains NUL: {source:?}"));
    }
    if source.starts_with('/') || source.starts_with("~/") || source.starts_with('~') {
        return Err(format!(
            "bundle source must be relative inside the bundle (got {source:?})"
        ));
    }
    // Windows drive (`C:`) defensively rejected for portability.
    if source.len() >= 2
        && source.as_bytes()[1] == b':'
        && source.as_bytes()[0].is_ascii_alphabetic()
    {
        return Err(format!("bundle source must not be absolute: {source:?}"));
    }
    if has_dotdot(source) {
        return Err(format!("bundle source contains `..`: {source:?}"));
    }
    for bad in ["\n", "\r"] {
        if source.contains(bad) {
            return Err(format!(
                "bundle source contains control character: {source:?}"
            ));
        }
    }
    Ok(())
}

/// Validate an `env_schema` reference (must be `env/<name>.toml` inside the
/// bundle).
pub fn validate_env_schema_ref(ref_path: &str) -> Result<(), String> {
    validate_bundle_source(ref_path)?;
    if !ref_path.starts_with("env/") {
        return Err(format!(
            "env_schema must live under `env/` (got {ref_path:?})"
        ));
    }
    if !ref_path.ends_with(".toml") {
        return Err(format!("env_schema must end in `.toml` (got {ref_path:?})"));
    }
    Ok(())
}

/// Validate a project path.
///
/// Portable form `~/...` is preferred (expanded to `$HOME` at plan time).
/// Absolute paths are accepted when they contain no `..` (needed for
/// disposable fixtures under `/tmp`), but paths that escape via traversal
/// are always rejected. Bare usernames (`/home/<user>`) are never invented:
/// capture converts `$HOME`-prefixed paths to `~/...` at generation time.
pub fn validate_project_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("project path must not be empty".into());
    }
    if has_nul(path) {
        return Err(format!("project path contains NUL: {path:?}"));
    }
    if has_dotdot(path) {
        return Err(format!("project path contains `..`: {path:?}"));
    }
    if path == "~" || path == "~/" {
        return Err("project path `~` has no remainder".into());
    }
    for bad in ["\n", "\r"] {
        if path.contains(bad) {
            return Err(format!("project path contains control character: {path:?}"));
        }
    }
    Ok(())
}

/// Convert an absolute path to portable form: when `abs` starts with `home`,
/// return `~/<rest>`; otherwise return `abs` unchanged.
///
/// Never invents a username; the replacement is purely prefix-based.
pub fn to_portable(abs: &str, home: &str) -> String {
    let home = home.trim_end_matches('/');
    if abs == home {
        return "~".into();
    }
    if let Some(rest) = abs.strip_prefix(&format!("{home}/")) {
        return format!("~/{}", rest);
    }
    abs.to_string()
}

/// Validate an octal mode string (`"0600"`, `"0644"`, `"0755"`).
///
/// Accepts 3- or 4-digit octal with optional leading `0`. Returns the parsed
/// mode bits on success.
pub fn parse_mode(mode: &str) -> Result<u32, String> {
    if mode.is_empty() {
        return Err("mode must not be empty".into());
    }
    let m = mode.strip_prefix('0').unwrap_or(mode);
    // After stripping one leading zero, require 3-4 octal digits.
    let digits = if mode.starts_with('0') {
        mode.len() - 1
    } else {
        mode.len()
    };
    if !(3..=4).contains(&digits) {
        return Err(format!(
            "mode must be a 3- or 4-digit octal string (got {mode:?})"
        ));
    }
    if !m.chars().all(|c| ('0'..='7').contains(&c)) {
        return Err(format!("mode must be octal digits only (got {mode:?})"));
    }
    let _ = m;
    u32::from_str_radix(mode.trim_start_matches('0'), 8)
        .or_else(|_| u32::from_str_radix("0", 8))
        .map_err(|_| format!("mode is not valid octal: {mode:?}"))
        .and_then(|v| {
            if v > 0o7777 {
                Err(format!("mode out of range: {mode:?}"))
            } else {
                Ok(v)
            }
        })
}

/// Validate an environment variable name (`[A-Za-z_][A-Za-z0-9_]*`).
pub fn validate_env_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("variable name must not be empty".into());
    }
    if has_nul(name) {
        return Err(format!("variable name contains NUL: {name:?}"));
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return Err(format!("invalid variable name: {name:?}")),
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("invalid variable name: {name:?}"));
    }
    Ok(())
}

/// Validate a profile name (`[a-z0-9][a-z0-9-_]{0,63}`).
pub fn validate_profile_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("profile name must not be empty".into());
    }
    if name.len() > 64 {
        return Err(format!("profile name too long (max 64): {name:?}"));
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return Err(format!("invalid profile name: {name:?}")),
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Err(format!("invalid profile name: {name:?}"));
    }
    Ok(())
}

/// Validate an apt package name (`[a-z0-9][a-z0-9+.-]*`, no shell syntax).
pub fn validate_package_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("package name must not be empty".into());
    }
    if has_nul(name) {
        return Err(format!("package name contains NUL: {name:?}"));
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return Err(format!("invalid package name: {name:?}")),
    }
    if !chars
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '+' || c == '-' || c == '.')
    {
        return Err(format!("invalid package name: {name:?}"));
    }
    Ok(())
}

/// Validate a `dnf`/`rpm`/`pacman` package name.
///
/// Broader than the apt grammar (RPM names may start with an uppercase
/// letter, e.g. `NetworkManager`, and both ecosystems use `_` and `:`) but
/// still T16-safe: ASCII alphanumeric start, `[A-Za-z0-9+._:-]`
/// continuation, no `..`, no whitespace, no shell metacharacters, no path
/// separators — fixed argv can never become a shell.
pub fn validate_native_package_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("package name must not be empty".into());
    }
    if name.len() > 128 || name.contains('\0') || name.contains("..") {
        return Err(format!("invalid package name: {name:?}"));
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return Err(format!("invalid package name: {name:?}")),
    }
    if !chars.all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.' || c == '_' || c == ':'
    }) {
        return Err(format!("invalid package name: {name:?}"));
    }
    Ok(())
}

/// Validate a systemd user unit name (`[A-Za-z0-9:_.@-]+\.service`, v1 only
/// `.service` user units).
pub fn validate_service_unit(unit: &str) -> bool {
    if unit.is_empty() || unit.len() > 128 || unit.contains('\0') || unit.contains("..") {
        return false;
    }
    if !unit.ends_with(".service") {
        return false;
    }
    let stem = &unit[..unit.len() - ".service".len()];
    if stem.is_empty() {
        return false;
    }
    stem.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '@' | '-'))
}

/// Validate a `secret://` reference (`secret://<namespace>/<path...>`).
pub fn validate_secret_ref(r: &str) -> Result<(), String> {
    let rest = r
        .strip_prefix("secret://")
        .ok_or_else(|| format!("secret ref must start with `secret://` (got {r:?})"))?;
    if rest.is_empty() {
        return Err("secret ref has empty path".into());
    }
    if has_nul(r) || has_dotdot(r) {
        return Err(format!("secret ref contains unsafe components: {r:?}"));
    }
    if !rest.contains('/') {
        return Err(format!(
            "secret ref must contain a namespace path (`secret://ns/path`, got {r:?})"
        ));
    }
    for part in rest.split('/') {
        if part.is_empty() {
            return Err(format!("secret ref has empty component: {r:?}"));
        }
    }
    Ok(())
}
