//! configctl binary entry point (P1 scan + P2 capture; both read-only w.r.t.
//! the source environment).

use clap::{Parser, Subcommand};
use configctl_cli::commands::{capture, plan, scan};
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
    };
    code
}
