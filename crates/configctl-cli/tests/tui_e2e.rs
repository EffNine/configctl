//! Non-TTY refusal e2e for `configctl tui` (docs/TUI.md §7): without a real
//! terminal the command must exit 2 with a one-line message and write
//! nothing — never emit alternate-screen escapes into a pipe.

#[test]
fn run_tui_without_tty_refuses_with_exit_2() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    // Under `cargo test` stdout is captured (not a TTY), so the refusal path
    // is exercised naturally.
    let out = configctl_cli::commands::tui::run_tui(
        None,
        Some(state.to_str().unwrap()),
        Some(tmp.path()),
    );
    assert_eq!(out.exit_code, 2);
    let msg = out.error.expect("refusal must carry a message");
    assert!(msg.contains("real terminal"), "message: {msg}");
    assert!(msg.contains("configctl status"), "message: {msg}");
    // Nothing written: no state directory, no files, no escape sequences.
    assert!(!state.exists());
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
}

#[test]
fn binary_tui_without_tty_exits_2_with_message() {
    let tmp = tempfile::tempdir().unwrap();
    let state = tmp.path().join("state");
    let bin = env!("CARGO_BIN_EXE_configctl");
    let output = std::process::Command::new(bin)
        .arg("--state-dir")
        .arg(&state)
        .arg("tui")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn configctl");
    assert_eq!(output.status.code(), Some(2), "must exit 2 without a TTY");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("real terminal"), "stderr: {stderr}");
    assert!(stderr.contains("configctl tui"), "stderr: {stderr}");
    // The TUI never writes to stdout (no escape sequences into the pipe).
    assert!(output.stdout.is_empty(), "stdout must stay empty");
    assert!(!state.exists(), "refusal must not create the state dir");
}
