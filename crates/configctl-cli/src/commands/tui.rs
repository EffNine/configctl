//! `configctl tui` — read-only interactive dashboard (T1, docs/TUI.md).
//!
//! The command refuses to run without a real terminal (exit 2) so pipes and
//! scripts never receive alternate-screen escape sequences; scripts keep
//! using the CLI subcommands. Once past the TTY gate, the TUI only calls
//! read paths (`status` state queries, `verify`, `env explain`, `doctor`).

use crate::tui;
use configctl_core::command::StdCommandRunner;
use std::io::IsTerminal;
use std::path::Path;

/// Result of `configctl tui`: 0 normal quit, 2 usage / not a TTY.
pub struct TuiOutcome {
    pub exit_code: i32,
    pub error: Option<String>,
}

/// Run the T1 dashboard. Returns immediately (writing nothing) when stdin or
/// stdout is not a terminal.
pub fn run_tui(
    profile: Option<&str>,
    state_dir_override: Option<&str>,
    home_override: Option<&Path>,
) -> TuiOutcome {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return TuiOutcome {
            exit_code: 2,
            error: Some(
                "configctl tui needs a real terminal (stdin/stdout is not a TTY); scripts should \
                 use the CLI subcommands, e.g. `configctl status`, `configctl verify`, \
                 `configctl env explain`, `configctl doctor`"
                    .to_string(),
            ),
        };
    }
    let runner = StdCommandRunner::new();
    let mut app = tui::app::App::new(profile, state_dir_override, home_override);
    match tui::run(&mut app, &runner) {
        Ok(()) => TuiOutcome {
            exit_code: 0,
            error: None,
        },
        Err(e) => TuiOutcome {
            exit_code: 1,
            error: Some(format!("terminal error: {e}")),
        },
    }
}
