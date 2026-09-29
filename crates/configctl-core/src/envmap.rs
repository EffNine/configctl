//! Environment-source mapping for `configctl env explain` (v1.2, phase E1).
//!
//! Read-only by construction: this module parses shell startup files with a
//! deliberately conservative, non-evaluating line scanner and reports what it
//! finds. It never sources, evaluates, expands, or executes anything, and it
//! never retains the value of a variable that looks like a secret.
//!
//! Recognized line forms (top level only — keyword depth must be zero):
//!
//! ```text
//! export NAME=VALUE      # POSIX/Bash/Zsh export
//! NAME=VALUE             # plain assignment
//! ```
//!
//! Everything else is classified `manual` (conditional, continued, or
//! expansion-bearing), `special` (behaviour-defining, e.g. `PATH`), `secret`
//! (name/shape looks sensitive), or `structure` (`source`, `.`, `eval`,
//! `alias`). Nothing is guessed: unrecognized lines are reported, not dropped.

use serde::Serialize;
use std::collections::BTreeMap;

/// Maximum bytes read from a single source file.
pub const MAX_SOURCE_BYTES: usize = 256 * 1024;

/// Shell family a source belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellFamily {
    Bash,
    Zsh,
    Sh,
    Unknown,
}

/// A known shell-startup source kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Bashrc,
    BashProfile,
    Profile,
    Zshrc,
    Zshenv,
    Xprofile,
    EnvironmentD,
    Other,
}

impl SourceKind {
    /// Shell family this file is read by.
    pub fn family(self) -> ShellFamily {
        match self {
            SourceKind::Bashrc | SourceKind::BashProfile => ShellFamily::Bash,
            SourceKind::Zshrc | SourceKind::Zshenv => ShellFamily::Zsh,
            SourceKind::Profile => ShellFamily::Sh,
            SourceKind::Xprofile => ShellFamily::Unknown,
            SourceKind::EnvironmentD => ShellFamily::Unknown,
            SourceKind::Other => ShellFamily::Unknown,
        }
    }

    /// Plain-language description of when the file is read (beginner output).
    pub fn read_when(self) -> &'static str {
        match self {
            SourceKind::Bashrc => "read by every Bash terminal",
            SourceKind::BashProfile => "read by login Bash shells",
            SourceKind::Profile => "read at login",
            SourceKind::Zshrc => "read by every Zsh terminal",
            SourceKind::Zshenv => "read by every Zsh shell",
            SourceKind::Xprofile => "read by some X11 desktop sessions",
            SourceKind::EnvironmentD => "read by desktop apps and user services",
            SourceKind::Other => "read by a shell",
        }
    }

    /// Whether this file participates in consolidation by default (§6.2).
    /// `~/.xprofile` is offered but off by default.
    pub fn participates_default(self) -> bool {
        matches!(
            self,
            SourceKind::Bashrc
                | SourceKind::BashProfile
                | SourceKind::Profile
                | SourceKind::Zshrc
                | SourceKind::Zshenv
                | SourceKind::EnvironmentD
        )
    }

    /// Relative path under `$HOME` for this kind, when it has a fixed one.
    pub fn rel_path(self) -> Option<&'static str> {
        match self {
            SourceKind::Bashrc => Some(".bashrc"),
            SourceKind::BashProfile => Some(".bash_profile"),
            SourceKind::Profile => Some(".profile"),
            SourceKind::Zshrc => Some(".zshrc"),
            SourceKind::Zshenv => Some(".zshenv"),
            SourceKind::Xprofile => Some(".xprofile"),
            SourceKind::EnvironmentD | SourceKind::Other => None,
        }
    }
}

/// Classification of one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineClass {
    /// A simple top-level assignment that may be consolidated.
    Managed,
    /// A behaviour-defining variable (`PATH`, `PS1`, …); reported, never moved.
    Special,
    /// Conditional, continued, or expansion-bearing; reported, never touched.
    Manual,
    /// Looks sensitive; only the name is retained, never the value.
    Secret,
    /// `source`/`.`/`eval`/`alias` — structure, not a declaration.
    Structure,
}

impl LineClass {
    /// Stable machine string.
    pub fn as_str(self) -> &'static str {
        match self {
            LineClass::Managed => "managed",
            LineClass::Special => "special",
            LineClass::Manual => "manual",
            LineClass::Secret => "secret",
            LineClass::Structure => "structure",
        }
    }
}

/// One classified line from a source.
#[derive(Debug, Clone, Serialize)]
pub struct Declaration {
    /// Variable name, or a short structural token for non-assignments.
    pub name: String,
    /// 1-based line number.
    pub line: usize,
    pub class: LineClass,
    /// Why a line was not treated as a plain assignment (when applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unquoted value — present only for `managed`/`special`, never `secret`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// True when `class == secret`.
    pub secret: bool,
}

/// One parsed source file.
#[derive(Debug, Clone, Serialize)]
pub struct EnvSource {
    /// Portable locator (`~/.bashrc`).
    pub path: String,
    pub kind: SourceKind,
    pub family: ShellFamily,
    /// Lower runs earlier in a shell session.
    pub read_order: u32,
    pub declarations: Vec<Declaration>,
}

/// The complete read-only view produced by `configctl env explain`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct EnvSourceMap {
    pub sources: Vec<EnvSource>,
}

/// A same-name collision between two sources.
#[derive(Debug, Clone, Serialize)]
pub struct Conflict {
    pub name: String,
    pub winner: String,
    pub winner_value: String,
    pub shadowed: String,
    pub shadowed_value: String,
}

impl EnvSourceMap {
    /// Names declared in more than one source with differing effective values.
    pub fn conflicts(&self) -> Vec<Conflict> {
        let mut by_name: BTreeMap<String, Vec<(&str, &str)>> = BTreeMap::new();
        for s in &self.sources {
            for d in &s.declarations {
                if d.class == LineClass::Managed {
                    if let Some(v) = &d.value {
                        by_name
                            .entry(d.name.clone())
                            .or_default()
                            .push((s.path.as_str(), v.as_str()));
                    }
                }
            }
        }
        let mut out = Vec::new();
        for (name, sites) in by_name {
            if sites.len() < 2 {
                continue;
            }
            let (winner_path, winner_val) = sites[sites.len() - 1];
            let (shadow_path, shadow_val) = sites[0];
            if winner_val != shadow_val {
                out.push(Conflict {
                    name,
                    winner: winner_path.to_string(),
                    winner_value: winner_val.to_string(),
                    shadowed: shadow_path.to_string(),
                    shadowed_value: shadow_val.to_string(),
                });
            }
        }
        out
    }

    /// `name -> (value, winning source path)` for non-secret assignments.
    /// Later-read sources win; within a source, later lines win.
    pub fn effective(&self) -> BTreeMap<String, (String, String)> {
        let mut map: BTreeMap<String, (String, String)> = BTreeMap::new();
        for s in &self.sources {
            for d in &s.declarations {
                if d.class == LineClass::Managed {
                    if let Some(v) = &d.value {
                        map.insert(d.name.clone(), (v.clone(), s.path.clone()));
                    }
                }
            }
        }
        map
    }

    /// Names that look like secrets (name only; values are never retained).
    pub fn secret_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .sources
            .iter()
            .flat_map(|s| s.declarations.iter())
            .filter(|d| d.secret)
            .map(|d| d.name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

/// Variables that define shell behaviour and are never consolidated (§6.4).
const SPECIAL_NAMES: &[&str] = &[
    "PATH",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "IFS",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "PS1",
    "PS2",
    "PS4",
    "CDPATH",
    "SHELLOPTS",
    "BASHOPTS",
    "FIGNORE",
    "GLOBIGNORE",
];

/// Case-insensitive name fragments that mark a variable as secret-like.
const SECRET_NAME_FRAGMENTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "APIKEY",
    "API_KEY",
    "PRIVATE",
    "ACCESS_KEY",
    "CREDENTIAL",
    "_AUTH",
    "AUTH_",
    "BEARER",
];

/// Value prefixes that mark a token-shaped secret regardless of name.
const SECRET_VALUE_PREFIXES: &[&str] = &["-----BEGIN", "sk-", "ghp_", "github_pat_", "AKIA", "eyJ"];

fn is_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_NAME_FRAGMENTS.iter().any(|f| upper.contains(f))
}

fn is_secret_value(value: &str) -> bool {
    let v = value.trim();
    SECRET_VALUE_PREFIXES.iter().any(|p| v.starts_with(p))
}

fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Strip exactly one layer of matching single or double quotes, resolving only
/// `\"`/`\\` inside double quotes. Anything else is returned unchanged.
fn unquote(raw: &str) -> String {
    let t = raw.trim();
    let bytes = t.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            let inner = &t[1..t.len() - 1];
            if first == b'"' {
                let mut out = String::with_capacity(inner.len());
                let mut escaped = false;
                for c in inner.chars() {
                    if escaped {
                        out.push(c);
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else {
                        out.push(c);
                    }
                }
                if escaped {
                    out.push('\\');
                }
                return out;
            }
            return inner.to_string();
        }
    }
    t.to_string()
}

/// True when the value contains shell expansion or substitution.
fn has_expansion(value: &str) -> bool {
    value.contains('$') || value.contains('`') || value.contains('*') || value.contains('?')
}

/// Only an unmatched quote is ambiguous for our purposes.
fn unbalanced_quotes(value: &str) -> bool {
    let mut in_s = false;
    let mut in_d = false;
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_d => escaped = true,
            '\'' if !in_d => in_s = !in_s,
            '"' if !in_s => in_d = !in_d,
            _ => {}
        }
    }
    in_s || in_d
}

/// Parse a source file body into an [`EnvSource`]. Pure and total.
pub fn parse_source(name: &str, content: &str, kind: SourceKind, read_order: u32) -> EnvSource {
    let mut declarations = Vec::new();
    let mut depth: usize = 0;
    let mut continuation = false;

    for (idx, raw_line) in content.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let trimmed = line.trim();

        // Blank / comment lines carry no declaration and never open a block.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let continued_now = continuation;
        continuation = trimmed.ends_with('\\');

        let opens = opens_block(trimmed);
        let closes = closes_block(trimmed);
        // Evaluate nesting against the pre-update depth for this line.
        let nested = depth > 0;
        depth = depth.saturating_add(opens).saturating_sub(closes);

        if continued_now || continuation {
            declarations.push(manual_decl(trimmed, lineno, "continued line"));
            continue;
        }
        if nested || opens > 0 || closes > 0 {
            declarations.push(manual_decl(trimmed, lineno, "conditional or nested block"));
            continue;
        }

        if let Some(d) = parse_assignment(trimmed, lineno) {
            declarations.push(d);
        } else if is_structure(trimmed) {
            declarations.push(Declaration {
                name: structure_token(trimmed),
                line: lineno,
                class: LineClass::Structure,
                reason: Some("shell structure, not a declaration".into()),
                value: None,
                secret: false,
            });
        } else {
            declarations.push(manual_decl(
                trimmed,
                lineno,
                "not a simple top-level assignment",
            ));
        }
    }

    EnvSource {
        path: name.to_string(),
        kind,
        family: kind.family(),
        read_order,
        declarations,
    }
}

fn manual_decl(line: &str, lineno: usize, reason: &str) -> Declaration {
    Declaration {
        name: short_token(line),
        line: lineno,
        class: LineClass::Manual,
        reason: Some(reason.to_string()),
        value: None,
        secret: false,
    }
}

fn short_token(line: &str) -> String {
    let first = line.split_whitespace().next().unwrap_or("");
    let token: String = first.chars().take(24).collect();
    if token.is_empty() {
        "<line>".to_string()
    } else {
        token
    }
}

fn opens_block(line: &str) -> usize {
    let first = line.split_whitespace().next().unwrap_or("");
    let opens = matches!(first, "if" | "for" | "while" | "until" | "case" | "select");
    // Function definitions: `name() {` or `function name {`.
    let func = first == "function" || line.contains("() {") || line.ends_with("()");
    (opens as usize) + (func as usize)
}

fn closes_block(line: &str) -> usize {
    let first = line.split_whitespace().next().unwrap_or("");
    let kw = matches!(first, "fi" | "done" | "esac");
    let brace = line == "}" || line.starts_with("} ");
    (kw as usize) + (brace as usize)
}

fn is_structure(line: &str) -> bool {
    let first = line.split_whitespace().next().unwrap_or("");
    matches!(first, "source" | "eval" | "alias" | ".")
}

fn structure_token(line: &str) -> String {
    let first = line.split_whitespace().next().unwrap_or("");
    first.to_string()
}

fn parse_assignment(line: &str, lineno: usize) -> Option<Declaration> {
    let body = line.strip_prefix("export ").map(str::trim).unwrap_or(line);
    // Reject anything that is not a single NAME=VALUE token.
    if body.starts_with(' ') || body.starts_with('\t') {
        return None;
    }
    let (name, raw_value) = body.split_once('=')?;
    let name = name.trim();
    if !is_valid_name(name) {
        return None;
    }

    if SPECIAL_NAMES.contains(&name) {
        return Some(Declaration {
            name: name.to_string(),
            line: lineno,
            class: LineClass::Special,
            reason: Some("behaviour-defining variable".into()),
            value: Some(unquote(raw_value)),
            secret: false,
        });
    }

    if unbalanced_quotes(raw_value) || has_expansion(raw_value) {
        return Some(Declaration {
            name: name.to_string(),
            line: lineno,
            class: LineClass::Manual,
            reason: Some("uses expansion or quoting that cannot be proven".into()),
            value: None,
            secret: false,
        });
    }

    let value = unquote(raw_value);
    if is_secret_name(name) || is_secret_value(&value) {
        return Some(Declaration {
            name: name.to_string(),
            line: lineno,
            class: LineClass::Secret,
            reason: Some("looks like a secret; managed by reference".into()),
            value: None,
            secret: true,
        });
    }

    Some(Declaration {
        name: name.to_string(),
        line: lineno,
        class: LineClass::Managed,
        reason: None,
        value: Some(value),
        secret: false,
    })
}

// ---------------------------------------------------------------------------
// Managed-artifact composition (v1.2 E2 building blocks — pure, no I/O)
// ---------------------------------------------------------------------------

/// Marker that opens the managed include block.
pub const INCLUDE_BEGIN: &str = "# >>> configctl env >>>";
/// Marker that closes the managed include block.
pub const INCLUDE_END: &str = "# <<< configctl env <<<";
/// Canonical shell env file, relative to `$HOME`.
pub const CANONICAL_REL: &str = ".config/configctl/env.sh";

/// Quote a value for the canonical POSIX file when it is not a bare-safe token.
fn quote_value(value: &str) -> String {
    let bare_safe = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-:+@".contains(c));
    if bare_safe {
        value.to_string()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// Render the canonical managed env file content for the given `NAME=VALUE`
/// pairs (sorted, de-duplicated by name; later input wins).
pub fn canonical_env_file(entries: &[(String, String)]) -> String {
    let mut map: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for (k, v) in entries {
        map.insert(k.as_str(), v.as_str());
    }
    let mut s = String::from(
        "# Managed by configctl (do not hand-edit managed entries)\n\
         # Generated from the profile/environment data; regenerate with\n\
         # `configctl env consolidate`.\n",
    );
    for (k, v) in map {
        s.push_str(&format!("{k}={}\n", quote_value(v)));
    }
    s
}

/// The marker-delimited include block that makes a shell read the canonical file.
pub fn include_block() -> String {
    format!(
        "{INCLUDE_BEGIN}\n\
         # Managed by configctl. Edit values with `configctl env consolidate`; this\n\
         # block itself is replaced on apply, not appended.\n\
         if [ -f \"$HOME/{CANONICAL_REL}\" ]; then\n    \
         . \"$HOME/{CANONICAL_REL}\"\n\
         fi\n\
         {INCLUDE_END}\n"
    )
}

/// True when the content already contains a configctl include block, or a
/// foreign/partial block using the same markers (both mean "do not touch").
pub fn has_include_block(content: &str) -> bool {
    content.contains(INCLUDE_BEGIN) || content.contains(INCLUDE_END)
}

/// Append the include block at the end of a file body, idempotently. When the
/// file already has a marker block it is returned unchanged; callers must
/// treat a changed return value as needing a backup + atomic write.
pub fn ensure_include_block(content: &str) -> String {
    if has_include_block(content) {
        return content.to_string();
    }
    let mut s = content.to_string();
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    if !s.is_empty() {
        s.push('\n');
    }
    s.push_str(&include_block());
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> EnvSource {
        parse_source("~/.bashrc", content, SourceKind::Bashrc, 1)
    }

    #[test]
    fn simple_export_is_managed() {
        let s = parse("export EDITOR=nano\n");
        assert_eq!(s.declarations.len(), 1);
        let d = &s.declarations[0];
        assert_eq!(d.name, "EDITOR");
        assert_eq!(d.class, LineClass::Managed);
        assert_eq!(d.value.as_deref(), Some("nano"));
    }

    #[test]
    fn plain_assignment_and_quotes_are_handled() {
        let s = parse("LANG=\"en_US.UTF-8\"\nGREETING='hi there'\n");
        assert_eq!(s.declarations[0].value.as_deref(), Some("en_US.UTF-8"));
        assert_eq!(s.declarations[1].value.as_deref(), Some("hi there"));
    }

    #[test]
    fn path_is_special_not_managed() {
        let s = parse("export PATH=\"$PATH:$HOME/.local/bin\"\n");
        assert_eq!(s.declarations[0].name, "PATH");
        assert_eq!(s.declarations[0].class, LineClass::Special);
    }

    #[test]
    fn expansion_forces_manual() {
        let s = parse("HOST_ALIAS=$(hostname)\n");
        assert_eq!(s.declarations[0].class, LineClass::Manual);
        assert!(s.declarations[0].value.is_none());
    }

    #[test]
    fn continuation_is_manual() {
        let s = parse("FOO=bar \\\n  baz\n");
        assert!(s
            .declarations
            .iter()
            .all(|d| d.class == LineClass::Manual || d.name == "FOO"));
        assert!(s.declarations[0].class == LineClass::Manual);
    }

    #[test]
    fn nested_conditional_lines_are_manual() {
        let src = "if [ -f /etc/profile ]; then\n  source /etc/profile\n  EDITOR=vim\nfi\n";
        let s = parse(src);
        // Everything inside the block is manual; the block is never entered.
        assert!(s.declarations.iter().all(|d| d.class == LineClass::Manual));
    }

    #[test]
    fn secret_names_never_retain_values() {
        let s = parse("export GITHUB_TOKEN=ghp_abcdef123456\n");
        let d = &s.declarations[0];
        assert_eq!(d.class, LineClass::Secret);
        assert!(d.secret);
        assert!(d.value.is_none());
    }

    #[test]
    fn value_shaped_secret_is_detected_by_shape() {
        let s = parse("export K=eyJhbGciOiJIUzI1NiJ9\n");
        assert_eq!(s.declarations[0].class, LineClass::Secret);
    }

    #[test]
    fn source_and_alias_are_structure() {
        let s = parse("source ~/.extra\nalias ll='ls -l'\n");
        assert_eq!(s.declarations[0].class, LineClass::Structure);
        assert_eq!(s.declarations[1].class, LineClass::Structure);
    }

    #[test]
    fn later_line_wins_within_a_source() {
        let src = "export EDITOR=nano\nexport EDITOR=vim\n";
        let map = EnvSourceMap {
            sources: vec![parse(src)],
        };
        let eff = map.effective();
        assert_eq!(eff.get("EDITOR").map(|(v, _)| v.as_str()), Some("vim"));
    }

    #[test]
    fn later_source_wins_across_sources() {
        let map = EnvSourceMap {
            sources: vec![
                parse_source("~/.bashrc", "export EDITOR=nano\n", SourceKind::Bashrc, 1),
                parse_source("~/.profile", "export EDITOR=vim\n", SourceKind::Profile, 3),
            ],
        };
        let eff = map.effective();
        assert_eq!(
            eff.get("EDITOR"),
            Some(&("vim".to_string(), "~/.profile".to_string()))
        );
    }

    #[test]
    fn conflicts_report_shadowing() {
        let map = EnvSourceMap {
            sources: vec![
                parse_source("~/.bashrc", "export EDITOR=nano\n", SourceKind::Bashrc, 1),
                parse_source("~/.profile", "export EDITOR=vim\n", SourceKind::Profile, 3),
            ],
        };
        let c = map.conflicts();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].name, "EDITOR");
        assert_eq!(c[0].winner, "~/.profile");
        assert_eq!(c[0].winner_value, "vim");
    }

    #[test]
    fn equal_values_are_not_a_conflict() {
        let map = EnvSourceMap {
            sources: vec![
                parse_source("~/.bashrc", "export EDITOR=vim\n", SourceKind::Bashrc, 1),
                parse_source("~/.profile", "export EDITOR=vim\n", SourceKind::Profile, 3),
            ],
        };
        assert!(map.conflicts().is_empty());
    }

    #[test]
    fn canonical_file_is_sorted_and_quoted() {
        let entries = vec![
            ("LANG".to_string(), "en_US.UTF-8".to_string()),
            ("EDITOR".to_string(), "vim".to_string()),
            ("MOTD".to_string(), "hello world".to_string()),
        ];
        let out = canonical_env_file(&entries);
        assert!(out.contains("EDITOR=vim\n"));
        assert!(out.contains("LANG=en_US.UTF-8\n"));
        assert!(out.contains("MOTD=\"hello world\"\n"));
        // EDITOR sorts before LANG, which sorts before MOTD.
        let e = out.find("EDITOR=").unwrap();
        let l = out.find("LANG=").unwrap();
        let m = out.find("MOTD=").unwrap();
        assert!(e < l && l < m);
    }

    #[test]
    fn include_block_is_idempotent() {
        let base = "export EDITOR=vim\n";
        let once = ensure_include_block(base);
        assert!(once.contains(INCLUDE_BEGIN));
        assert!(once.contains(INCLUDE_END));
        let twice = ensure_include_block(&once);
        assert_eq!(once, twice);
        assert!(has_include_block(&once));
    }

    #[test]
    fn foreign_marker_blocks_are_never_re_written() {
        let foreign = format!("{INCLUDE_BEGIN}\n. /somewhere/else\n{INCLUDE_END}\n");
        assert!(has_include_block(&foreign));
        assert_eq!(ensure_include_block(&foreign), foreign);
    }
}
