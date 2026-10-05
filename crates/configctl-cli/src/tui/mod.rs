//! `configctl tui` — read-only interactive dashboard (T1).
//!
//! `run` owns the terminal lifecycle through `ratatui::run`: alternate
//! screen + raw mode are entered on start and restored on normal exit *and*
//! on panic. The loop polls for input with a 250 ms timeout so `Ctrl+C` and
//! window resizes stay responsive without a busy spin; only key presses are
//! handled (`Release`/`Repeat` events are ignored by `App::handle_key`).

pub mod app;
pub mod ui;

use configctl_core::command::CommandRunner;
use ratatui::crossterm::event::{self, Event};
use std::io;
use std::time::Duration;

/// Input tick while waiting for keys (T1: no background refresh loops).
const TICK: Duration = Duration::from_millis(250);

/// Run the dashboard until the user quits, restoring the terminal after.
pub fn run(app: &mut app::App, runner: &dyn CommandRunner) -> io::Result<()> {
    ratatui::run(|terminal| event_loop(terminal, app, runner))
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut app::App,
    runner: &dyn CommandRunner,
) -> io::Result<()> {
    // Load the first tab before the first frame so Overview never flashes
    // "loading…" on a healthy machine.
    app.ensure_loaded(runner);
    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, app))?;
        if event::poll(TICK)? {
            // Resizes (and any other non-key events) are picked up by the
            // next draw; there is no state to update for them.
            if let Event::Key(key) = event::read()? {
                app.handle_key(key, runner);
            }
        }
    }
    Ok(())
}
