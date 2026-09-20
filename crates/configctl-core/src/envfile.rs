//! Bounded, pure-text `.env` parser for discovery.
//!
//! `.env` files are configuration data, **not** executable shell code. The
//! parser never executes anything, performs no shell expansion, and no
//! variable interpolation. It is safe against malformed input: bad lines
//! yield structured warnings, and scanning continues.

use std::fmt;
use std::io;

/// Per-variable parse record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineStatus {
    /// A well-formed `KEY=VALUE` entry.
    Ok,
    /// A line that could not be interpreted as a key/value entry.
    Malformed,
}

/// One parsed environment variable. The raw value is held in private storage
/// so it can feed the in-process secret detector; no public output type ever
/// carries the value itself.
#[derive(Clone)]
pub struct ParsedVariable {
    pub name: String,
    value: Option<String>,
    pub status: LineStatus,
    /// 1-based line number in the source file.
    pub line: usize,
}

impl fmt::Debug for ParsedVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never reveal the value; a derived Debug would be unsafe here.
        f.debug_struct("ParsedVariable")
            .field("name", &self.name)
            .field("line", &self.line)
            .field("value_present", &!self.value_is_empty())
            .finish()
    }
}

impl ParsedVariable {
    /// Whether the variable has a non-empty value (never the value itself).
    pub fn value_is_empty(&self) -> bool {
        match &self.value {
            Some(v) => v.is_empty(),
            None => true,
        }
    }

    /// Length of the raw value, for entropy heuristics.
    pub fn value_len(&self) -> usize {
        self.value.as_deref().map_or(0, str::len)
    }

    /// Run a closure over the raw value without ever returning it.
    pub fn with_value<T>(&self, f: impl FnOnce(&str) -> T) -> T {
        match self.value.as_deref() {
            Some(v) => f(v),
            None => f(""),
        }
    }
}

/// A fully parsed `.env` file.
#[derive(Debug, Default, Clone)]
pub struct ParsedEnvFile {
    /// Variables in source order (duplicates preserved).
    pub variables: Vec<ParsedVariable>,
    /// Malformed-line records: (line number, reason code). No content kept.
    pub malformed: Vec<(usize, MalformedKind)>,
    /// Number of blank/comment lines skipped.
    pub skipped: usize,
}

/// Reason code for a malformed line (no content is retained).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MalformedKind {
    /// `KEY=value` with an invalid variable name.
    InvalidName,
    /// No `=` separator on a non-blank, non-comment line.
    MissingSeparator,
    /// Line longer than the per-line cap.
    TooLong,
}

impl fmt::Display for MalformedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            MalformedKind::InvalidName => "invalid variable name",
            MalformedKind::MissingSeparator => "missing '=' separator",
            MalformedKind::TooLong => "line exceeds length cap",
        };
        f.write_str(s)
    }
}

/// Parser limits.
#[derive(Debug, Clone, Copy)]
pub struct ParseLimits {
    /// Maximum bytes read from the file.
    pub max_bytes: usize,
    /// Maximum number of variable lines retained.
    pub max_variables: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024,
            max_variables: 10_000,
        }
    }
}

const MAX_LINE: usize = 4096;

/// Parse `content` into a [`ParsedEnvFile`] under `limits`.
///
/// Returns even when individual lines are malformed; those are recorded in
/// `parsed.malformed`. Scanning never panics on input.
pub fn parse_env(content: &str, limits: &ParseLimits) -> ParsedEnvFile {
    // Drop a leading BOM so `FOO=bar` is not seen as `\u{feff}FOO=bar`.
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let content = if content.len() > limits.max_bytes {
        safe_take(content, limits.max_bytes)
    } else {
        content.to_string()
    };

    let mut parsed = ParsedEnvFile::default();

    for (idx, raw_line) in content.lines().enumerate() {
        if parsed.variables.len() >= limits.max_variables {
            break;
        }
        let line_no = idx + 1;
        let line = raw_line.trim();

        if line.is_empty() || line.starts_with('#') {
            parsed.skipped += 1;
            continue;
        }
        if line.len() > MAX_LINE {
            parsed.malformed.push((line_no, MalformedKind::TooLong));
            continue;
        }

        // Optional `export ` prefix.
        let rest = line.strip_prefix("export ").unwrap_or(line);
        let eq = match find_name_end(rest) {
            Some(end) => end,
            None => {
                parsed
                    .malformed
                    .push((line_no, MalformedKind::MissingSeparator));
                continue;
            }
        };
        let name_part = &rest[..eq];
        let name = name_part.trim_end();
        if !is_valid_name(name) {
            parsed.malformed.push((line_no, MalformedKind::InvalidName));
            continue;
        }

        let raw_value = rest[eq + 1..].trim_start();
        let value = strip_outer_quotes(raw_value);

        parsed.variables.push(ParsedVariable {
            name: name.to_string(),
            value: Some(value.to_string()),
            status: LineStatus::Ok,
            line: line_no,
        });
    }
    parsed
}

/// Drop leading BOM and newlines inside the value region are already
/// removed by `lines()`; nothing else to normalize.
fn safe_take(s: &str, max: usize) -> String {
    let end = s
        .char_indices()
        .take_while(|(i, _)| *i < max)
        .last()
        .map_or(0, |(i, c)| i + c.len_utf8());
    s[..end.min(s.len())].to_string()
}

/// Index of the first top-level `=` (not inside single/double quotes), or
/// None when no separator exists.
fn find_name_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut in_single = false;
    let mut in_double = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b'=' if !in_single && !in_double => return Some(i),
            _ => {}
        }
    }
    None
}

/// Remove one layer of matching outer quotes; unbalanced quotes keep their
/// remainder (a plain-text interpretation, never execution).
fn strip_outer_quotes(v: &str) -> &str {
    let b = v.as_bytes();
    if b.len() >= 2 {
        if b[0] == b'"' && b[b.len() - 1] == b'"' {
            return &v[1..v.len() - 1];
        }
        if b[0] == b'\'' && b[b.len() - 1] == b'\'' {
            return &v[1..v.len() - 1];
        }
    }
    v
}

/// A variable name is `[A-Za-z_][A-Za-z0-9_]*`.
fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Read a file with a byte cap and parse it.
pub fn parse_file(
    path: &std::path::Path,
    limits: &ParseLimits,
) -> Result<ParsedEnvFile, io::Error> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; limits.max_bytes + 1];
    let n = f.read(&mut buf)?;
    let buf = &buf[..n.min(limits.max_bytes)];
    let text = String::from_utf8_lossy(buf);
    Ok(parse_env(&text, limits))
}

/// Deduplicated, sorted variable names.
pub fn variable_names(parsed: &ParsedEnvFile) -> Vec<String> {
    let mut names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for v in &parsed.variables {
        names.insert(&v.name);
    }
    names.iter().map(|s| s.to_string()).collect()
}
