//! `CommandRunner` — the only way any configctl crate may run a subprocess.
//!
//! Guarantees:
//! - explicit argv, never a shell
//! - bounded stdout/stderr (byte cap)
//! - hard timeout
//! - scrubbed environment (no inherited values that look secret)
//! - error details are static text, never command output

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// One subprocess invocation request.
#[derive(Debug, Clone)]
pub struct CommandRequest {
    /// Program path (resolved; may be a bare name searched on PATH).
    pub program: PathBuf,
    /// Arguments. No shell interpolation, ever.
    pub args: Vec<String>,
    /// Working directory, if any.
    pub cwd: Option<PathBuf>,
    /// Per-invocation timeout (falls back to the runner default when `None`).
    pub timeout: Option<Duration>,
    /// Per-invocation output cap (falls back to the runner default when `None`).
    pub output_cap: Option<usize>,
}

impl CommandRequest {
    pub fn new(
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(|a| a.as_ref().to_string()).collect(),
            cwd: None,
            timeout: None,
            output_cap: None,
        }
    }

    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn output_cap(mut self, cap: usize) -> Self {
        self.output_cap = Some(cap);
        self
    }
}

/// Captured subprocess result. Output is capped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandOutput {
    /// Process exit code, `None` when killed by timeout or spawn failed.
    pub status: Option<i32>,
    /// Captured stdout (capped, lossily UTF-8).
    pub stdout: String,
    /// Captured stderr (capped, lossily UTF-8).
    pub stderr: String,
    /// True when either stream hit its cap.
    pub truncated: bool,
    /// True when the process was killed for exceeding the timeout.
    pub timed_out: bool,
}

/// Errors from the runner. Detail is static, never contains command output.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandError {
    /// The program could not be spawned.
    SpawnFailed,
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("subprocess could not be spawned")
    }
}

impl std::fmt::Debug for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CommandError::SpawnFailed => "SpawnFailed",
        })
    }
}

/// The only trait through which configctl crates may run subprocesses.
pub trait CommandRunner: Send + Sync {
    fn run(&self, req: &CommandRequest) -> Result<CommandOutput, CommandError>;
}

/// Build the scrubbed command for a request (env: PATH/HOME/LANG only).
fn build(req: &CommandRequest) -> Command {
    let mut cmd = Command::new(&req.program);
    cmd.args(&req.args);
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }
    cmd.stdin(Stdio::null());
    cmd.env_clear();
    cmd.env("PATH", std::env::var_os("PATH").unwrap_or_default());
    cmd.env("HOME", std::env::var_os("HOME").unwrap_or_default());
    cmd.env("LANG", "C");
    cmd
}

/// Read one stream to a cap.
fn read_capped(reader: &mut impl std::io::Read, cap: usize) -> (String, bool) {
    let mut buf = Vec::with_capacity(cap.min(8192));
    let mut total = 0usize;
    let mut tmp = [0u8; 8192];
    loop {
        let room = cap.saturating_sub(total);
        if room == 0 {
            return (lossy_utf8(&buf), true);
        }
        let n = match reader.read(&mut tmp[..room.min(8192)]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        total += n;
        buf.extend_from_slice(&tmp[..n]);
    }
    (lossy_utf8(&buf), false)
}

fn lossy_utf8(buf: &[u8]) -> String {
    // Lossy conversion keeps the cap byte-honest and the output printable.
    String::from_utf8_lossy(buf).into_owned()
}

/// Default runner backed by `std::process::Command`.
#[derive(Default)]
pub struct StdCommandRunner {
    default_timeout: Duration,
    default_output_cap: usize,
}

impl StdCommandRunner {
    pub fn new() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            default_output_cap: 256 * 1024,
        }
    }

    pub fn with_defaults(timeout: Duration, output_cap: usize) -> Self {
        Self {
            default_timeout: timeout,
            default_output_cap: output_cap,
        }
    }
}

impl CommandRunner for StdCommandRunner {
    fn run(&self, req: &CommandRequest) -> Result<CommandOutput, CommandError> {
        let timeout = req.timeout.unwrap_or(self.default_timeout);
        let cap = req.output_cap.unwrap_or(self.default_output_cap);

        let mut cmd = build(req);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child: Child = cmd.spawn().map_err(|_| CommandError::SpawnFailed)?;

        // Pump both pipes to caps on two worker threads so the process can
        // never deadlock on a full pipe buffer.
        let (so_tx, so_rx) = std::sync::mpsc::channel::<(String, bool)>();
        let (se_tx, se_rx) = std::sync::mpsc::channel::<(String, bool)>();
        let cap1 = cap;
        let cap2 = cap;
        {
            let mut so_pipe = child.stdout.take().expect("piped stdout");
            std::thread::spawn(move || {
                let (s, t) = read_capped(&mut so_pipe, cap1);
                let _ = so_tx.send((s, t));
            });
            let mut se_pipe = child.stderr.take().expect("piped stderr");
            std::thread::spawn(move || {
                let (s, t) = read_capped(&mut se_pipe, cap2);
                let _ = se_tx.send((s, t));
            });
        }

        // Wait for the child with a hard deadline; kill best-effort on expiry.
        let status = wait_with_deadline(&mut child, timeout);
        // Drain the pipes (already capped on the reader threads).
        let (stdout, out_trunc) = so_rx.recv_timeout(timeout).unwrap_or_default();
        let (stderr, err_trunc) = se_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or_default();

        Ok(CommandOutput {
            status,
            stdout,
            stderr,
            truncated: out_trunc || err_trunc,
            timed_out: status.is_none(),
        })
    }
}

/// Wait for the child, killing it (best-effort) if the deadline passes.
///
/// Polls in small slices so the deadline check actually runs; a process that
/// ignores the deadline is still reported as timed out (`status: None`) even
/// if the kill did not take effect immediately. The post-kill reap is itself
/// bounded: an unkillable (uninterruptible-sleep) child can never hang the
/// scanner — it is reported timed-out and left for init to reap.
fn wait_with_deadline(child: &mut Child, timeout: Duration) -> Option<i32> {
    let start = std::time::Instant::now();
    let deadline_poll = timeout / 4;
    let last_poll = timeout.max(Duration::from_millis(200));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) => {
                if start.elapsed() >= last_poll {
                    // Best-effort kill; report timeout honestly.
                    let _ = child.kill();
                    // Bounded reap: 2s grace, then give up waiting (never hang).
                    let reap_start = std::time::Instant::now();
                    while reap_start.elapsed() < Duration::from_secs(2) {
                        match child.try_wait() {
                            Ok(Some(_)) | Err(_) => break,
                            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                        }
                    }
                    return None;
                }
                if start.elapsed() >= deadline_poll {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            Err(_) => return None,
        }
    }
}

/// A scripted in-memory runner for tests: records argv, returns canned
/// outputs in order (or the default when the list is exhausted).
#[derive(Debug)]
pub struct FakeCommandRunner {
    calls: std::sync::Mutex<Vec<CommandRequest>>,
    canned: std::sync::Mutex<Vec<CommandOutput>>,
    default_output: CommandOutput,
}

impl Default for FakeCommandRunner {
    fn default() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            canned: std::sync::Mutex::new(Vec::new()),
            default_output: CommandOutput::default(),
        }
    }
}

impl FakeCommandRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a canned output to return on the next call.
    pub fn queue(&self, out: CommandOutput) {
        self.canned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(out);
    }

    /// Recorded calls (for test assertions).
    pub fn recorded(&self) -> Vec<CommandRequest> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn next_output(&self) -> CommandOutput {
        let mut c = self.canned.lock().unwrap_or_else(|e| e.into_inner());
        if c.is_empty() {
            self.default_output.clone()
        } else {
            c.remove(0)
        }
    }
}

impl CommandRunner for FakeCommandRunner {
    fn run(&self, req: &CommandRequest) -> Result<CommandOutput, CommandError> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(req.clone());
        Ok(self.next_output())
    }
}
