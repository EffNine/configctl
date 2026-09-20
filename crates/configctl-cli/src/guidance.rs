//! Plain-language guidance: `configctl guide`, `--explain` blocks, success
//! hints, and error help.
//!
//! Guidance is human-facing only. It is never emitted in `--json` mode, never
//! changes command behavior, and never touches the machine: the worst side
//! effect is one rate-limit timestamp under the state directory
//! (`ux.json`, `0600`).

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Shown at most once per topic per window.
const HINT_TTL_SECS: i64 = 24 * 60 * 60;

/// Environment kill switch: any value except `0`/`false` disables hints.
const HINTS_ENV: &str = "CONFIGCTL_NO_HINTS";

/// One guidance subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topic {
    Start,
    Scan,
    Capture,
    Profile,
    Plan,
    Apply,
    Verify,
    Rollback,
    Env,
    Secrets,
    Audit,
    Doctor,
    ExitCodes,
    Glossary,
}

impl Topic {
    pub const ALL: [Topic; 14] = [
        Topic::Start,
        Topic::Scan,
        Topic::Capture,
        Topic::Profile,
        Topic::Plan,
        Topic::Apply,
        Topic::Verify,
        Topic::Rollback,
        Topic::Env,
        Topic::Secrets,
        Topic::Audit,
        Topic::Doctor,
        Topic::ExitCodes,
        Topic::Glossary,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Topic::Start => "start",
            Topic::Scan => "scan",
            Topic::Capture => "capture",
            Topic::Profile => "profile",
            Topic::Plan => "plan",
            Topic::Apply => "apply",
            Topic::Verify => "verify",
            Topic::Rollback => "rollback",
            Topic::Env => "env",
            Topic::Secrets => "secrets",
            Topic::Audit => "audit",
            Topic::Doctor => "doctor",
            Topic::ExitCodes => "exit-codes",
            Topic::Glossary => "glossary",
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Topic::Start => "What configctl is and where to begin",
            Topic::Scan => "Read-only discovery: what lives where",
            Topic::Capture => "Turn this machine into a profile bundle",
            Topic::Profile => "Inspect and validate profile bundles",
            Topic::Plan => "See exactly what would change (no mutation)",
            Topic::Apply => "Execute an approved plan, journaled and backed up",
            Topic::Verify => "Check the machine still matches the profile",
            Topic::Rollback => "Undo file changes from backups",
            Topic::Env => "Environment files and variables",
            Topic::Secrets => "References, never values",
            Topic::Audit => "Safety check for a repository",
            Topic::Doctor => "Diagnostics and interrupted-apply recovery",
            Topic::ExitCodes => "What each exit code means",
            Topic::Glossary => "Words used across configctl",
        }
    }

    pub fn from_key(raw: &str) -> Option<Topic> {
        let key = raw.trim().to_ascii_lowercase();
        let key = key.as_str();
        Some(match key {
            "start" | "help" | "overview" => Topic::Start,
            "scan" => Topic::Scan,
            "capture" => Topic::Capture,
            "profile" | "profiles" => Topic::Profile,
            "plan" => Topic::Plan,
            "apply" => Topic::Apply,
            "verify" => Topic::Verify,
            "rollback" | "undo" => Topic::Rollback,
            "env" | "environment" => Topic::Env,
            "secrets" | "secret" => Topic::Secrets,
            "audit" => Topic::Audit,
            "doctor" => Topic::Doctor,
            "exit-codes" | "exits" | "exit" => Topic::ExitCodes,
            "glossary" => Topic::Glossary,
            _ => return None,
        })
    }

    fn text(self) -> &'static str {
        match self {
            Topic::Start => include_str!("guide/start.md"),
            Topic::Scan => include_str!("guide/scan.md"),
            Topic::Capture => include_str!("guide/capture.md"),
            Topic::Profile => include_str!("guide/profile.md"),
            Topic::Plan => include_str!("guide/plan.md"),
            Topic::Apply => include_str!("guide/apply.md"),
            Topic::Verify => include_str!("guide/verify.md"),
            Topic::Rollback => include_str!("guide/rollback.md"),
            Topic::Env => include_str!("guide/env.md"),
            Topic::Secrets => include_str!("guide/secrets.md"),
            Topic::Audit => include_str!("guide/audit.md"),
            Topic::Doctor => include_str!("guide/doctor.md"),
            Topic::ExitCodes => include_str!("guide/exit-codes.md"),
            Topic::Glossary => include_str!("guide/glossary.md"),
        }
    }
}

/// Context attached to one command invocation.
#[derive(Debug, Clone)]
pub struct Meta {
    pub topic: Topic,
    pub json: bool,
    pub quiet: bool,
    pub state_dir: PathBuf,
}

/// `configctl guide [topic]`.
pub fn render_guide(topic: Option<&str>) -> Result<String, String> {
    match topic {
        None => Ok(index()),
        Some(t) => match Topic::from_key(t) {
            Some(topic) => Ok(topic.text().to_string()),
            None => Err(format!(
                "unknown guide topic {t:?}\navailable topics: {}",
                Topic::ALL
                    .iter()
                    .map(|t| t.key())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        },
    }
}

fn index() -> String {
    let mut out = String::from("configctl guide — plain-language help\n\nTopics:\n");
    for topic in Topic::ALL {
        out.push_str(&format!("  {:<11} {}\n", topic.key(), topic.summary()));
    }
    out.push_str(
        "\nRun `configctl guide <topic>` for one subject.\n\
         Most commands also accept --explain for a short \"what this means\" note.\n",
    );
    out
}

/// Short note appended to human output when `--explain` is passed.
pub fn explain(topic: Topic) -> &'static str {
    match topic {
        Topic::Start => {
            "what this means: configctl is read-only until you approve a plan. Start with `configctl scan <path>` or browse `configctl guide`."
        }
        Topic::Scan => {
            "what this means: nothing here changed your machine. The report is a picture of what exists; continue with capture when ready."
        }
        Topic::Capture => {
            "what this means: this wrote a profile bundle only. Review profile.toml; when it looks right, `configctl plan <bundle>` shows what applying it would change."
        }
        Topic::Profile => {
            "what this means: validation only reads. A profile is your desired state; plan/apply compare it against the machine."
        }
        Topic::Plan => {
            "what this means: nothing was changed. This plan is a snapshot with an ID and a hash; approval binds to those. Review conflicts before applying."
        }
        Topic::Apply => {
            "what this means: apply executes exactly what the plan listed — nothing more. File writes are backed up, so rollback can restore them."
        }
        Topic::Verify => {
            "what this means: this is a comparison, not a repair. DRIFT/MISSING tell you to plan and apply; UNMANAGED means configctl does not own that file."
        }
        Topic::Rollback => {
            "what this means: only file changes are restored from backups; package and service changes are reported, not undone."
        }
        Topic::Env => {
            "what this means: only names and classifications are shown — values are never printed. env scan does not import anything."
        }
        Topic::Secrets => {
            "what this means: values stay in your keyring; profiles, plans, and logs carry only secret:// references."
        }
        Topic::Audit => {
            "what this means: findings are prompts to review. Nothing was modified."
        }
        Topic::Doctor => {
            "what this means: diagnostics only. If an apply was interrupted, doctor says what can be recovered."
        }
        Topic::ExitCodes => {
            "what this means: exit codes are the script contract; 4 and 5 mean nothing changed, 3 means the machine differs from the profile."
        }
        Topic::Glossary => {
            "what this means: short definitions for the words used in configctl output."
        }
    }
}

/// One useful next step, shown as a hint after success (when allowed).
pub fn hint(topic: Topic) -> Option<&'static str> {
    match topic {
        Topic::Scan => Some("capture what you see with `configctl capture`"),
        Topic::Capture => Some("validate the bundle with `configctl profile validate <bundle>`"),
        Topic::Profile => Some("see changes with `configctl plan <bundle>`"),
        Topic::Plan => Some("apply this plan with `configctl apply --last`"),
        Topic::Apply => Some("check the result with `configctl verify <profile>`"),
        Topic::Verify => Some("drift? `configctl plan <profile>` shows how to fix it"),
        Topic::Doctor => Some("exit codes are explained in `configctl guide exit-codes`"),
        _ => None,
    }
}

/// Plain-language interpretation for a non-zero exit code.
pub fn error_help(code: u8) -> &'static str {
    match code {
        1 => {
            "an unexpected error. If this was apply, run `configctl doctor` to see whether anything was left half-done."
        }
        2 => "the command or input was not valid. Nothing was changed.",
        3 => {
            "the machine differs from the profile. Run `configctl plan <profile>` to see the changes."
        }
        4 => {
            "approval was not given, so nothing changed. Re-run with --yes to approve non-interactively."
        }
        5 => {
            "configctl refused because something was unsafe or not owned by this profile; nothing changed. Re-run `configctl plan`, review conflicts, and use --adopt only for files you want managed."
        }
        6 => "the secret backend (keyring) is not available; no values were read or written.",
        7 => {
            "a required system tool (apt/systemd/git) is missing; nothing changed. See `configctl doctor`."
        }
        8 => "this requires privileges that were not available; nothing changed.",
        _ => "the command failed; run `configctl doctor` to inspect the current state.",
    }
}

/// Print guidance for a finished command. Human mode only.
pub fn emit(meta: &Meta, exit_code: u8, explain_requested: bool) {
    if meta.json {
        return;
    }
    if exit_code == 0 {
        if explain_requested {
            println!("\n{}", explain(meta.topic));
        }
        if meta.quiet || hint(meta.topic).is_none() {
            return;
        }
        if !std::io::stderr().is_terminal() {
            return;
        }
        let now = unix_now().unwrap_or(0);
        if hints_allowed_at(Some(&meta.state_dir), meta.topic, now) {
            if let Some(h) = hint(meta.topic) {
                eprintln!("\nhint: {h}");
                eprintln!("      more: configctl guide {}", meta.topic.key());
            }
            record_hint_at(Some(&meta.state_dir), meta.topic, now);
        }
    } else {
        eprintln!("\nwhat this means: {}", error_help(exit_code));
        eprintln!("next: configctl guide exit-codes");
    }
}

/// Hints are allowed when not disabled by env, and not shown for this topic
/// within the last [`HINT_TTL_SECS`]. A missing state directory never blocks
/// a hint (nothing to persist to yet).
pub fn hints_allowed_at(state_dir: Option<&Path>, topic: Topic, now: i64) -> bool {
    if let Some(v) = std::env::var_os(HINTS_ENV) {
        if !matches!(v.to_str(), Some("0") | Some("false")) {
            return false;
        }
    }
    let Some(dir) = state_dir else {
        return true;
    };
    let Ok(text) = std::fs::read_to_string(dir.join("ux.json")) else {
        return true;
    };
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(&text) else {
        return true;
    };
    match doc
        .get("hints")
        .and_then(|h| h.get(topic.key()))
        .and_then(|v| v.as_i64())
    {
        Some(last) => now.saturating_sub(last) >= HINT_TTL_SECS,
        None => true,
    }
}

/// Best-effort rate-limit timestamp; never fails the command.
pub fn record_hint_at(state_dir: Option<&Path>, topic: Topic, now: i64) {
    let Some(dir) = state_dir else {
        return;
    };
    if !dir.is_dir() {
        return;
    }
    let path = dir.join("ux.json");
    let mut doc = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .unwrap_or_else(|| serde_json::json!({"schema_version": 1, "hints": {}}));
    if !doc.get("hints").map(|h| h.is_object()).unwrap_or(false) {
        doc["hints"] = serde_json::json!({});
    }
    doc["hints"][topic.key()] = serde_json::json!(now);

    let body = format!("{doc}\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
        {
            use std::io::Write;
            let _ = f.write_all(body.as_bytes());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(&path, body);
    }
}

fn unix_now() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_topic_renders_and_has_explain() {
        for topic in Topic::ALL {
            let text = render_guide(Some(topic.key())).unwrap();
            assert!(text.len() > 200, "guide {topic:?} too short");
            assert!(!explain(topic).is_empty(), "explain {topic:?} empty");
            assert_eq!(Topic::from_key(topic.key()), Some(topic));
        }
    }

    #[test]
    fn index_lists_every_topic() {
        let index = render_guide(None).unwrap();
        for topic in Topic::ALL {
            assert!(index.contains(topic.key()), "index missing {topic:?}");
            assert!(index.contains(topic.summary()));
        }
    }

    #[test]
    fn unknown_topic_is_an_error_with_choices() {
        let err = render_guide(Some("nonsense")).unwrap_err();
        assert!(err.contains("unknown guide topic"));
        assert!(err.contains("start"));
        assert!(err.contains("exit-codes"));
    }

    #[test]
    fn aliases_resolve() {
        assert_eq!(Topic::from_key("undo"), Some(Topic::Rollback));
        assert_eq!(Topic::from_key("environment"), Some(Topic::Env));
        assert_eq!(Topic::from_key("help"), Some(Topic::Start));
        assert_eq!(Topic::from_key(" EXIT "), Some(Topic::ExitCodes));
    }

    #[test]
    fn error_help_covers_contract_codes() {
        for code in 0u8..=8 {
            assert!(!error_help(code).is_empty(), "code {code} has no help");
        }
    }

    #[test]
    fn hint_rate_limit_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let t0 = 1_800_000_000i64;
        assert!(hints_allowed_at(Some(dir), Topic::Plan, t0));
        record_hint_at(Some(dir), Topic::Plan, t0);
        assert!(!hints_allowed_at(Some(dir), Topic::Plan, t0 + 60));
        assert!(!hints_allowed_at(
            Some(dir),
            Topic::Plan,
            t0 + HINT_TTL_SECS - 1
        ));
        assert!(hints_allowed_at(Some(dir), Topic::Plan, t0 + HINT_TTL_SECS));
        assert!(hints_allowed_at(Some(dir), Topic::Scan, t0 + 60));
    }

    #[test]
    fn missing_state_dir_never_blocks_or_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        assert!(hints_allowed_at(Some(&missing), Topic::Apply, 0));
        record_hint_at(Some(&missing), Topic::Apply, 0);
        assert!(!missing.exists());
    }

    #[test]
    fn corrupt_ux_file_does_not_block() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("ux.json"), "not json").unwrap();
        assert!(hints_allowed_at(Some(tmp.path()), Topic::Plan, 0));
    }
}
