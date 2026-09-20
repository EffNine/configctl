//! configctl binary entry point (P1 scan + P2 capture; both read-only w.r.t.
//! the source environment).

use clap::{Parser, Subcommand};
use configctl_cli::commands::{apply, capture, plan, scan, verify};
use configctl_core::command::StdCommandRunner;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "configctl")]
#[command(about = "Linux-first environment manager (scan + capture + plan; apply in P4)")]
#[command(version = "0.1.0")]
struct Cli {
    /// Override the state directory (default ~/.local/state/configctl)
    #[arg(long = "state-dir", global = true, value_name = "DIR")]
    state_dir: Option<String>,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Read-only discovery of projects, .env files, configs, git status
    Scan {
        /// Scan roots (default: conservative project roots under $HOME)
        #[arg(value_name = "PATH")]
        roots: Vec<String>,
        /// Additional scan roots
        #[arg(long = "root", value_name = "PATH")]
        extra_roots: Vec<String>,
        /// Maximum recursion depth
        #[arg(long, value_name = "N")]
        depth: Option<usize>,
        /// Machine-readable JSON on stdout
        #[arg(long)]
        json: bool,
        /// Suppress non-essential output
        #[arg(short, long)]
        quiet: bool,
        /// Increase diagnostic detail
        #[arg(short, long)]
        verbose: bool,
    },
    /// Capture observed state as a declarative, portable profile bundle
    Capture {
        /// Profile name (defaults to the output directory basename)
        #[arg(value_name = "NAME")]
        name: Option<String>,
        /// Scan roots to capture from (may repeat; `--root` is an alias)
        #[arg(long = "from", value_name = "PATH")]
        from: Vec<String>,
        /// Additional scan roots (alias for `--from`)
        #[arg(long = "root", value_name = "PATH")]
        extra_roots: Vec<String>,
        /// Output directory for the profile bundle
        #[arg(long = "output", alias = "out", value_name = "DIR")]
        output: Option<String>,
        /// Overwrite a non-empty output directory
        #[arg(long)]
        force: bool,
        /// Maximum recursion depth for discovery
        #[arg(long, value_name = "N")]
        depth: Option<usize>,
        /// Analyze without writing the profile
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// Machine-readable JSON on stdout
        #[arg(long)]
        json: bool,
        /// Suppress non-essential output
        #[arg(short, long)]
        quiet: bool,
        /// Increase diagnostic detail
        #[arg(short, long)]
        verbose: bool,
    },
    /// Show the deterministic diff between a profile and this machine (no mutation)
    Plan {
        /// Profile name or path to a profile bundle directory
        #[arg(value_name = "PROFILE")]
        profile: String,
        /// Machine-readable JSON on stdout
        #[arg(long)]
        json: bool,
        /// Exit 5 when the plan contains conflicts
        #[arg(long = "fail-on-conflict")]
        fail_on_conflict: bool,
        /// Increase diagnostic detail
        #[arg(short, long)]
        verbose: bool,
    },
    /// Execute exactly a persisted approved plan (the only mutating path)
    Apply {
        /// Plan ID produced by `configctl plan` (never a profile path)
        #[arg(value_name = "PLAN_ID")]
        plan: Option<String>,
        /// Explicit plan ID flag (alias for the positional)
        #[arg(long = "plan", value_name = "PLAN_ID")]
        plan_flag: Option<String>,
        /// Approve the current plan non-interactively
        #[arg(short, long)]
        yes: bool,
        /// Preview without writing
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// Take ownership of unmanaged targets (must be plan conflicts)
        #[arg(long = "adopt", value_name = "TARGET")]
        adopt: Vec<String>,
        /// Machine-readable JSON on stdout (requires --yes unless --dry-run)
        #[arg(long)]
        json: bool,
    },
    /// Compare a profile against this machine (read-only, never repairs)
    Verify {
        /// Profile name or path to a profile bundle directory
        #[arg(value_name = "PROFILE")]
        profile: String,
        /// Machine-readable JSON on stdout
        #[arg(long)]
        json: bool,
        /// Also fail on UNMANAGED / UNKNOWN findings
        #[arg(long)]
        strict: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runner = StdCommandRunner::new();

    let code = match &cli.command {
        None => {
            eprintln!("configctl: no command given (try `configctl scan`, `configctl capture`, or `configctl --help`)");
            ExitCode::from(2)
        }
        Some(Cmd::Scan {
            roots,
            extra_roots,
            depth,
            json,
            quiet,
            verbose,
        }) => {
            let out = scan::run_scan(roots, extra_roots, *depth, *json, *quiet, *verbose, &runner);
            match &out.error_envelope {
                Some(err) => {
                    if *json {
                        println!("{}", err.to_json());
                    } else {
                        eprintln!(
                            "error: {}",
                            err.errors.first().map(|w| w.message.as_str()).unwrap_or("")
                        );
                    }
                    ExitCode::from(2)
                }
                None => {
                    let registry = &out.registry;
                    if *json {
                        // P0 JSON envelope: {schema_version, command, status,
                        // data, warnings, errors}. `data` is the redacted scan
                        // result; the whole document is then redacted again.
                        let envelope = configctl_cli::render::Envelope::scan_ok(&out.result);
                        let json_str = envelope.to_json();
                        let json_str = registry.redact(&json_str);
                        println!("{json_str}");
                    } else {
                        let text = scan::render_human(&out.result, *quiet, *verbose);
                        let text = registry.redact(&text);
                        print!("{text}");
                    }
                    ExitCode::SUCCESS
                }
            }
        }
        Some(Cmd::Capture {
            name,
            from,
            extra_roots,
            output,
            force,
            depth,
            dry_run,
            json,
            quiet,
            verbose,
        }) => {
            let out = capture::run_capture(
                name.as_deref(),
                from,
                extra_roots,
                output.as_deref(),
                *force,
                *depth,
                *dry_run,
                None,
                &runner,
            );
            match &out.error_envelope {
                Some(err) => {
                    if *json {
                        let s = out.registry.redact(&err.to_json());
                        println!("{s}");
                    } else {
                        let msg = err.errors.first().map(|w| w.message.as_str()).unwrap_or("");
                        eprintln!("error: {}", out.registry.redact(msg));
                    }
                    ExitCode::from(2)
                }
                None => {
                    let registry = &out.registry;
                    if *json {
                        let res = out.result.as_ref().expect("capture result");
                        let envelope = configctl_cli::render::Envelope::capture_ok(
                            res,
                            &out.written,
                            &out.out_dir,
                            out.dry_run,
                        );
                        let json_str = envelope.to_json();
                        let json_str = registry.redact(&json_str);
                        println!("{json_str}");
                    } else {
                        let text = capture::render_human(&out, *verbose);
                        let text = registry.redact(&text);
                        if *quiet {
                            // Quiet: one-line summary only (still redacted).
                            if let Some(res) = &out.result {
                                let line = format!(
                                    "captured {} (projects {} files {} packages {} env {} secrets {})\n",
                                    res.profile.name,
                                    res.summary.projects,
                                    res.summary.files,
                                    res.summary.packages,
                                    res.summary.env_schemas,
                                    res.summary.secrets,
                                );
                                print!("{}", registry.redact(&line));
                            }
                        } else {
                            print!("{text}");
                        }
                    }
                    ExitCode::SUCCESS
                }
            }
        }
        Some(Cmd::Plan {
            profile,
            json,
            fail_on_conflict,
            verbose: _,
        }) => {
            let out = plan::run_plan(profile, cli.state_dir.as_deref(), None, &runner, None, None);
            match (&out.plan, &out.error) {
                (_, Some(err)) if out.plan.is_none() => {
                    if *json {
                        let env =
                            configctl_cli::render::Envelope::error("plan", &err.message, &err.hint);
                        println!("{}", env.to_json());
                    } else {
                        eprintln!("error: {}", err.message);
                    }
                    ExitCode::from(2)
                }
                (Some(p), _) => {
                    if *json {
                        let envelope = configctl_cli::render::Envelope::plan_ok(p);
                        let s = envelope.to_json();
                        println!("{s}");
                        let _: serde_json::Value =
                            serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
                    } else {
                        print!("{}", plan::render_human(p));
                    }
                    if *fail_on_conflict && !p.conflicts.is_empty() {
                        ExitCode::from(5)
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                (None, _) => ExitCode::from(1),
            }
        }
        Some(Cmd::Apply {
            plan: plan_arg,
            plan_flag,
            yes,
            dry_run,
            adopt,
            json,
        }) => {
            let out = apply::run_apply(
                plan_arg.as_deref(),
                plan_flag.as_deref(),
                cli.state_dir.as_deref(),
                None,
                *yes,
                *dry_run,
                adopt,
                *json,
                &runner,
            );
            match (&out.report, &out.error) {
                (Some(rep), _) => {
                    if *json {
                        let env =
                            configctl_cli::render::Envelope::ok("apply", apply::report_json(rep));
                        println!("{}", env.to_json());
                    } else {
                        print!("{}", apply::render_human(rep));
                    }
                    ExitCode::SUCCESS
                }
                (None, Some(e)) => {
                    if *json {
                        let env = configctl_cli::render::Envelope::error(
                            "apply",
                            &apply::error_message(e),
                            "see `configctl doctor` for recovery options",
                        );
                        println!("{}", env.to_json());
                    } else {
                        eprintln!("error: {}", apply::error_message(e));
                    }
                    ExitCode::from(out.exit_code as u8)
                }
                (None, None) => ExitCode::from(1),
            }
        }
        Some(Cmd::Verify {
            profile,
            json,
            strict,
        }) => {
            let out = verify::run_verify(profile, None, *strict, &runner);
            match (&out.report, &out.error) {
                (None, Some(e)) => {
                    if *json {
                        let env = configctl_cli::render::Envelope::error(
                            "verify",
                            e,
                            "fix the profile and retry",
                        );
                        println!("{}", env.to_json());
                    } else {
                        eprintln!("error: {e}");
                    }
                    ExitCode::from(2)
                }
                (Some(rep), _) => {
                    if *json {
                        let env = configctl_cli::render::Envelope::ok(
                            "verify",
                            serde_json::to_value(rep).unwrap_or_default(),
                        );
                        let s = env.to_json();
                        println!("{s}");
                        let _: serde_json::Value =
                            serde_json::from_str(&s).unwrap_or(serde_json::Value::Null);
                    } else {
                        print!("{}", verify::render_human(rep));
                    }
                    ExitCode::from(out.exit_code as u8)
                }
                (None, None) => ExitCode::from(1),
            }
        }
    };
    code
}
