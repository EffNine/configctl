//! Tests for the command runner and fake runner.

use configctl_core::command::{
    CommandOutput, CommandRequest, CommandRunner, FakeCommandRunner, StdCommandRunner,
};

#[test]
fn fake_runner_records_argv_and_returns_canned() {
    let fake = FakeCommandRunner::new();
    fake.queue(CommandOutput {
        status: Some(0),
        stdout: "/home/u/repo\n".into(),
        stderr: String::new(),
        truncated: false,
        timed_out: false,
    });
    let req = CommandRequest::new("git", ["status"]).cwd("/home/u/repo");
    let out = fake.run(&req).unwrap();
    assert_eq!(out.status, Some(0));
    assert_eq!(out.stdout.trim(), "/home/u/repo");

    let rec = fake.recorded();
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].program.display().to_string(), "git");
    assert_eq!(rec[0].args, vec!["status"]);
}

#[test]
fn fake_runner_shell_metacharacters_stay_literal() {
    // The runner never invokes a shell: metacharacters in argv must stay
    // literal, not be interpreted.
    let fake = FakeCommandRunner::new();
    let req = CommandRequest::new("git", ["check-ignore", "-q", "--", "file; rm -rf /"]);
    let _ = fake.run(&req).unwrap();
    let rec = fake.recorded();
    assert_eq!(
        rec[0].args,
        vec!["check-ignore", "-q", "--", "file; rm -rf /"]
    );
}

#[test]
fn std_runner_executes_fixed_argv() {
    let runner = StdCommandRunner::new();
    let out = runner.run(&CommandRequest::new("echo", ["hello"])).unwrap();
    assert_eq!(out.status, Some(0));
    assert_eq!(out.stdout.trim(), "hello");
}

#[test]
fn std_runner_missing_program_is_spawn_error() {
    let runner = StdCommandRunner::new();
    let res = runner.run(&CommandRequest::new("definitely-not-a-real-cmd-xyz", ["x"]));
    assert!(res.is_err());
}

#[test]
fn std_runner_output_cap_bounds_stream() {
    // `yes` produces unbounded output; the cap must bound it.
    let mut req = CommandRequest::new("yes", ["A"]).timeout(std::time::Duration::from_secs(5));
    req.output_cap = Some(100);
    let runner = StdCommandRunner::new();
    let out = runner.run(&req).unwrap();
    assert!(out.truncated, "output cap must be reported as truncated");
    assert!(out.stdout.len() <= 100, "stdout must not exceed cap");
}
