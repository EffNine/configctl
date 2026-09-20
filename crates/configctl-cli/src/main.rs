//! configctl binary entry point: Linux-first environment manager.
//!
//! Read-only commands (scan, capture, plan, verify, env, audit, doctor,
//! profile) never mutate the machine. Only `apply`, `rollback`, and
//! `secrets set/import` mutate, and only after explicit approval.

use clap::{Parser, Subcommand};
use configctl_cli::commands::{
    apply, audit, capture, doctor, env, init, plan, profile, rollback, scan, secrets, verify,
};
use configctl_core::command::StdCommandRunner;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "configctl")]
#[command(
    about = "Linux-first environment manager: discover, capture, plan, apply, verify, roll back"
)]
#[command(version)]
struct Cli {
    /// Override the state directory (default ~/.local/state/configctl)
    #[arg(long = "state-dir", global = true, value_name = "DIR")]
    state_dir: Option<String>,
    /// Add a plain-language "what this means" note to human output
    #[arg(long, global = true)]
    explain: bool,
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
        /// Worker pool size (clamped to a hard sanity ceiling)
        #[arg(long, value_name = "N")]
        workers: Option<usize>,
        /// Wall-clock budget, e.g. `20m`, `90s`, `2h`
        #[arg(long = "max-time", value_name = "DURATION")]
        max_time: Option<String>,
        /// Maximum files visited across all roots
        #[arg(long = "max-files", value_name = "N")]
        max_files: Option<u64>,
        /// Maximum content bytes read, e.g. `100GiB`, `512MiB`
        #[arg(long = "max-bytes", value_name = "BYTES")]
        max_bytes: Option<String>,
        /// Soft cap for scan-held buffers, e.g. `2GiB`
        #[arg(long = "max-memory", value_name = "BYTES")]
        max_memory: Option<String>,
        /// Allow crossing into other local mounts (default: stay put)
        #[arg(long = "follow-mounts")]
        follow_mounts: bool,
        /// Allow recursive scans of network mounts (default: record only)
        #[arg(long = "scan-network")]
        scan_network: bool,
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
        /// Worker pool size (clamped to a hard sanity ceiling)
        #[arg(long, value_name = "N")]
        workers: Option<usize>,
        /// Wall-clock budget, e.g. `20m`, `90s`, `2h`
        #[arg(long = "max-time", value_name = "DURATION")]
        max_time: Option<String>,
        /// Maximum files visited across all roots
        #[arg(long = "max-files", value_name = "N")]
        max_files: Option<u64>,
        /// Maximum content bytes read, e.g. `100GiB`, `512MiB`
        #[arg(long = "max-bytes", value_name = "BYTES")]
        max_bytes: Option<String>,
        /// Soft cap for scan-held buffers, e.g. `2GiB`
        #[arg(long = "max-memory", value_name = "BYTES")]
        max_memory: Option<String>,
        /// Allow crossing into other local mounts (default: stay put)
        #[arg(long = "follow-mounts")]
        follow_mounts: bool,
        /// Allow recursive scans of network mounts (default: record only)
        #[arg(long = "scan-network")]
        scan_network: bool,
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
    /// First-class .env discovery and schema verification (read-only)
    Env {
        #[command(subcommand)]
        cmd: EnvCmd,
    },
    /// Secret references backed by the Linux Secret Service (values never in argv/logs/JSON)
    Secrets {
        #[command(subcommand)]
        cmd: SecretsCmd,
    },
    /// Read-only safety audit (tracked secrets, key permissions, examples)
    Audit {
        /// Optional `git` submode (`configctl audit git [PATH...]`) or scan paths
        #[arg(value_name = "TARGET_OR_PATH")]
        target: Vec<String>,
        /// Fail with exit 3 on findings at or above this severity
        #[arg(long = "fail-on", value_name = "SEVERITY")]
        fail_on: Option<String>,
        /// Machine-readable JSON on stdout
        #[arg(long)]
        json: bool,
    },
    /// Roll back an applied plan from content-addressed backups (explicit only)
    Rollback {
        /// Plan ID, profile name (latest plan), or ~/... file target
        #[arg(value_name = "TARGET")]
        target: Option<String>,
        /// Explicit plan ID
        #[arg(long = "plan", value_name = "PLAN_ID")]
        plan_flag: Option<String>,
        /// Show rollback candidates without changing anything
        #[arg(long)]
        list: bool,
        /// Approve non-interactively
        #[arg(short, long)]
        yes: bool,
        /// Preview without writing
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// Machine-readable JSON on stdout (requires --yes unless --dry-run)
        #[arg(long)]
        json: bool,
    },
    /// Diagnostics: platform, backends, state, interrupted applies (read-only)
    Doctor {
        /// Machine-readable JSON on stdout
        #[arg(long)]
        json: bool,
    },
    /// Create config, profiles, and state directories (touches nothing else)
    Init {
        /// Default profile name for the new config
        #[arg(long = "profile", value_name = "NAME")]
        profile: Option<String>,
        /// Overwrite an existing config file
        #[arg(long)]
        force: bool,
        /// Machine-readable JSON on stdout
        #[arg(long)]
        json: bool,
    },
    /// Inspect and validate profile bundles (read-only, except migrate)
    Profile {
        #[command(subcommand)]
        cmd: ProfileCmd,
    },
    /// Plain-language help while you work: `configctl guide [topic]`
    Guide {
        /// Topic name (omit to list every topic)
        #[arg(value_name = "TOPIC")]
        topic: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// List known profiles
    List {
        #[arg(long)]
        json: bool,
    },
    /// Render the canonical profile (never values)
    Show {
        #[arg(value_name = "NAME_OR_PATH")]
        profile: String,
        #[arg(long)]
        json: bool,
    },
    /// Validate a profile bundle (all errors listed)
    Validate {
        #[arg(value_name = "NAME_OR_PATH")]
        profile: String,
        #[arg(long)]
        json: bool,
    },
    /// Explicit one-way schema migration
    Migrate {
        #[arg(value_name = "NAME_OR_PATH")]
        profile: String,
        #[arg(long = "to", value_name = "SCHEMA_VERSION")]
        to: u32,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum EnvCmd {
    /// Discover .env files and classify variables (names only, never values)
    Scan {
        #[arg(value_name = "PATH")]
        roots: Vec<String>,
        #[arg(long = "root", value_name = "PATH")]
        extra_roots: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// List discovered variables with classifications (names only)
    List {
        #[arg(value_name = "PATH")]
        roots: Vec<String>,
        #[arg(long = "root", value_name = "PATH")]
        extra_roots: Vec<String>,
        #[arg(long = "project", value_name = "NAME")]
        project: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Verify project env schemas against live .env files (read-only)
    Verify {
        #[arg(value_name = "PROFILE")]
        profile: Option<String>,
        #[arg(long = "project", value_name = "NAME")]
        project: Option<String>,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SecretsCmd {
    /// List secret references with backend status (never values)
    List {
        #[arg(value_name = "PROFILE")]
        profile: Option<String>,
        #[arg(long = "project", value_name = "NAME")]
        project: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Store a secret (value via hidden prompt or --stdin, never argv)
    Set {
        #[arg(value_name = "REF")]
        secret_ref: String,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show metadata, or the value with explicit --show (TTY or --force)
    Get {
        #[arg(value_name = "REF")]
        secret_ref: String,
        #[arg(long)]
        show: bool,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// Import secret candidates from .env files (never rewrites sources)
    Import {
        #[arg(value_name = "PATH")]
        paths: Vec<String>,
        #[arg(long = "dry-run")]
        dry_run: bool,
        #[arg(short, long)]
        yes: bool,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(Cmd::Guide { topic }) = &cli.command {
        return match configctl_cli::guidance::render_guide(topic.as_deref()) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(2)
            }
        };
    }
    let meta = command_meta(&cli);
    let explain = cli.explain;
    let code = run(cli);
    configctl_cli::guidance::emit(&meta, last_code(), explain);
    code
}

thread_local! {
    /// Numeric exit code of the just-finished command, recorded by `finish`
    /// so guidance can interpret the result after rendering.
    static LAST_CODE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

/// Return an exit code while recording its numeric value for guidance.
fn finish(code: u8) -> ExitCode {
    LAST_CODE.with(|c| c.set(code));
    ExitCode::from(code)
}

fn last_code() -> u8 {
    LAST_CODE.with(|c| c.get())
}

fn command_meta(cli: &Cli) -> configctl_cli::guidance::Meta {
    use configctl_cli::guidance::{Meta, Topic};
    let (topic, json, quiet) = match &cli.command {
        Some(Cmd::Scan { json, quiet, .. }) => (Topic::Scan, *json, *quiet),
        Some(Cmd::Capture { json, quiet, .. }) => (Topic::Capture, *json, *quiet),
        Some(Cmd::Plan { json, .. }) => (Topic::Plan, *json, false),
        Some(Cmd::Apply { json, .. }) => (Topic::Apply, *json, false),
        Some(Cmd::Verify { json, .. }) => (Topic::Verify, *json, false),
        Some(Cmd::Rollback { json, .. }) => (Topic::Rollback, *json, false),
        Some(Cmd::Env { cmd }) => match cmd {
            EnvCmd::Scan { json, .. } | EnvCmd::List { json, .. } | EnvCmd::Verify { json, .. } => {
                (Topic::Env, *json, false)
            }
        },
        Some(Cmd::Secrets { cmd }) => match cmd {
            SecretsCmd::List { json, .. }
            | SecretsCmd::Set { json, .. }
            | SecretsCmd::Get { json, .. }
            | SecretsCmd::Import { json, .. } => (Topic::Secrets, *json, false),
        },
        Some(Cmd::Audit { json, .. }) => (Topic::Audit, *json, false),
        Some(Cmd::Doctor { json }) => (Topic::Doctor, *json, false),
        Some(Cmd::Init { json, .. }) => (Topic::Start, *json, false),
        Some(Cmd::Profile { cmd }) => match cmd {
            ProfileCmd::List { json }
            | ProfileCmd::Show { json, .. }
            | ProfileCmd::Validate { json, .. }
            | ProfileCmd::Migrate { json, .. } => (Topic::Profile, *json, false),
        },
        Some(Cmd::Guide { .. }) | None => (Topic::Start, false, false),
    };
    Meta {
        topic,
        json,
        quiet,
        state_dir: configctl_core::state::resolve_state_dir(cli.state_dir.as_deref()),
    }
}

fn run(cli: Cli) -> ExitCode {
    let runner = StdCommandRunner::new();

    let code = match &cli.command {
        None => {
            eprintln!("configctl: no command given (try `configctl scan`, `configctl capture`, or `configctl --help`)");
            finish(2)
        }
        Some(Cmd::Guide { .. }) => {
            // Handled in `main` before `run` is entered.
            finish(0)
        }
        Some(Cmd::Scan {
            roots,
            extra_roots,
            depth,
            json,
            quiet,
            verbose,
            workers,
            max_time,
            max_files,
            max_bytes,
            max_memory,
            follow_mounts,
            scan_network,
        }) => {
            let gov_flags = scan::ScanGovernorFlags {
                workers: *workers,
                max_time: max_time.clone(),
                max_files: *max_files,
                max_bytes: max_bytes.clone(),
                max_memory: max_memory.clone(),
                follow_mounts: *follow_mounts,
                scan_network: *scan_network,
            };
            let governor = match scan::governor_from_flags(&gov_flags) {
                Ok(b) => b,
                Err(e) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "scan",
                                &e,
                                "check resource flags"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    return finish(2);
                }
            };
            let out = scan::run_scan_with_governor(roots, extra_roots, *depth, governor, &runner);
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
                    finish(2)
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
                    finish(0)
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
            workers,
            max_time,
            max_files,
            max_bytes,
            max_memory,
            follow_mounts,
            scan_network,
        }) => {
            let gov_flags = capture::ScanGovernorFlags {
                workers: *workers,
                max_time: max_time.clone(),
                max_files: *max_files,
                max_bytes: max_bytes.clone(),
                max_memory: max_memory.clone(),
                follow_mounts: *follow_mounts,
                scan_network: *scan_network,
            };
            let governor = match capture::governor_from_flags(&gov_flags) {
                Ok(b) => b,
                Err(e) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "capture",
                                &e,
                                "check resource flags"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    return finish(2);
                }
            };
            let out = capture::run_capture_with_governor(
                name.as_deref(),
                from,
                extra_roots,
                output.as_deref(),
                *force,
                *depth,
                *dry_run,
                None,
                governor,
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
                    finish(2)
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
                    finish(0)
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
                    finish(2)
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
                        finish(5)
                    } else {
                        finish(0)
                    }
                }
                (None, _) => finish(1),
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
                    finish(0)
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
                    finish(out.exit_code as u8)
                }
                (None, None) => finish(1),
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
                    finish(2)
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
                    finish(out.exit_code as u8)
                }
                (None, None) => finish(1),
            }
        }
        Some(Cmd::Env { cmd }) => match cmd {
            EnvCmd::Scan {
                roots,
                extra_roots,
                json,
            } => match env::run_env_scan(roots, extra_roots, None, &runner) {
                Err(e) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "env scan",
                                &e,
                                "pass scan paths"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    finish(2)
                }
                Ok(view) => {
                    if *json {
                        let data = serde_json::json!({
                            "files": view.files, "variables": view.variables,
                            "secrets": view.secrets, "config_values": view.config_values,
                            "entries": view.entries.iter().map(|(p, v, c)| serde_json::json!({"project": p, "variable": v, "classification": c})).collect::<Vec<_>>(),
                        });
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::ok("env scan", data).to_json()
                        );
                    } else {
                        print!("{}", env::render_scan_human(&view));
                    }
                    finish(0)
                }
            },
            EnvCmd::List {
                roots,
                extra_roots,
                project,
                json,
            } => match env::run_env_scan(roots, extra_roots, None, &runner) {
                Err(e) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "env list",
                                &e,
                                "pass scan paths"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    finish(2)
                }
                Ok(view) => {
                    if *json {
                        let entries: Vec<_> = view.entries.iter()
                                .filter(|(p, _, _)| project.as_deref().map(|f| p == f).unwrap_or(true))
                                .map(|(p, v, c)| serde_json::json!({"project": p, "variable": v, "classification": c}))
                                .collect();
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::ok(
                                "env list",
                                serde_json::json!({"entries": entries})
                            )
                            .to_json()
                        );
                    } else {
                        print!("{}", env::render_list_human(&view, project.as_deref()));
                    }
                    finish(0)
                }
            },
            EnvCmd::Verify {
                profile,
                project,
                strict,
                json,
            } => {
                let out = env::run_env_verify(
                    profile.as_deref(),
                    project.as_deref(),
                    *strict,
                    None,
                    &runner,
                );
                if let Some(e) = &out.error {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "env verify",
                                e,
                                "fix the profile and retry"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    return finish(2);
                }
                if *json {
                    let data = serde_json::json!({"findings": out.findings.iter().map(|f| serde_json::json!({"project": f.project, "variable": f.variable, "kind": f.kind, "detail": f.detail})).collect::<Vec<_>>()});
                    println!(
                        "{}",
                        configctl_cli::render::Envelope::ok("env verify", data).to_json()
                    );
                } else {
                    print!("{}", env::render_verify_human(&out));
                }
                finish(out.exit_code as u8)
            }
        },
        Some(Cmd::Secrets { cmd }) => match cmd {
            SecretsCmd::List {
                profile,
                project,
                json,
            } => {
                let out = secrets::run_list(profile.as_deref(), project.as_deref(), &runner);
                if let Some(e) = &out.error {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "secrets list",
                                e,
                                "pass a profile"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    return finish(out.exit_code as u8);
                }
                if *json {
                    let data = serde_json::json!({"entries": out.entries.iter().map(|e| serde_json::json!({"project": e.project, "name": e.name, "ref": e.secret_ref, "status": e.status})).collect::<Vec<_>>()});
                    println!(
                        "{}",
                        configctl_cli::render::Envelope::ok("secrets list", data).to_json()
                    );
                } else {
                    print!("{}", secrets::render_list_human(&out));
                }
                finish(0)
            }
            SecretsCmd::Set {
                secret_ref,
                stdin,
                json,
            } => {
                let out = secrets::run_set(secret_ref, *stdin, None, &runner);
                if *json {
                    if let Some(e) = &out.error {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "secrets set",
                                e,
                                "see `configctl secrets set --help`"
                            )
                            .to_json()
                        );
                    } else {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::ok(
                                "secrets set",
                                serde_json::json!({"ref": out.secret_ref, "stored": true})
                            )
                            .to_json()
                        );
                    }
                } else if let Some(e) = &out.error {
                    eprintln!("error: {e}");
                } else {
                    println!("Stored {}.", out.secret_ref);
                }
                finish(out.exit_code as u8)
            }
            SecretsCmd::Get {
                secret_ref,
                show,
                force,
                json,
            } => {
                let out = secrets::run_get(secret_ref, *show, *force, *json, &runner);
                if *show {
                    // Explicit value output on stdout only (never JSON).
                    if let Some(v) = &out.value {
                        v.expose(|b| {
                            use std::io::Write;
                            let _ = std::io::stdout().write_all(b);
                            let _ = std::io::stdout().write_all(b"\n");
                        });
                        return finish(0);
                    }
                }
                if *json {
                    if let Some(e) = &out.error {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "secrets get",
                                e,
                                "check the ref and backend"
                            )
                            .to_json()
                        );
                    } else {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::ok(
                                "secrets get",
                                serde_json::json!({"ref": out.secret_ref, "status": out.status})
                            )
                            .to_json()
                        );
                    }
                } else if let Some(e) = &out.error {
                    eprintln!("error: {e}");
                } else {
                    println!("{}: {}", out.secret_ref, out.status);
                }
                finish(out.exit_code as u8)
            }
            SecretsCmd::Import {
                paths,
                dry_run,
                yes,
                json,
            } => {
                let out = secrets::run_import(
                    paths,
                    *dry_run,
                    *yes,
                    dirs::home_dir().as_deref(),
                    &runner,
                );
                if *json {
                    if let Some(e) = &out.error {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "secrets import",
                                e,
                                "check the backend and paths"
                            )
                            .to_json()
                        );
                    } else {
                        let data = serde_json::json!({
                            "candidates": out.candidates.iter().map(|c| serde_json::json!({"file": c.file, "name": c.name, "classification": c.classification})).collect::<Vec<_>>(),
                            "imported": out.imported, "ignored": out.ignored, "dry_run": out.dry_run,
                        });
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::ok("secrets import", data).to_json()
                        );
                    }
                } else {
                    if out.candidates.is_empty() {
                        println!("No secret candidates found.");
                    } else {
                        println!("Found {} potential secret(s).", out.candidates.len());
                        for c in &out.candidates {
                            println!("  {} — {} [{}]", c.file, c.name, c.classification);
                        }
                    }
                    if !out.imported.is_empty() {
                        println!(
                            "Imported {} value(s) into the secret backend.",
                            out.imported.len()
                        );
                    }
                    println!("Never deletes or rewrites originals. Nothing leaves this machine.");
                    if let Some(e) = &out.error {
                        eprintln!("error: {e}");
                    }
                }
                finish(out.exit_code as u8)
            }
        },
        Some(Cmd::Audit {
            target,
            fail_on,
            json,
        }) => {
            let (git_only, paths): (bool, Vec<String>) = match target.first().map(|s| s.as_str()) {
                Some("git") => (true, target[1..].to_vec()),
                _ => (false, target.clone()),
            };
            let out = audit::run_audit(&paths, &[], fail_on.as_deref(), git_only, &runner);
            if let Some(e) = &out.error {
                if *json {
                    println!(
                        "{}",
                        configctl_cli::render::Envelope::error("audit", e, "pass scan paths")
                            .to_json()
                    );
                } else {
                    eprintln!("error: {e}");
                }
                return finish(2);
            }
            if *json {
                let data = serde_json::json!({"findings": out.findings.iter().map(|f| serde_json::json!({"severity": f.severity, "code": f.code, "message": f.message})).collect::<Vec<_>>()});
                println!(
                    "{}",
                    configctl_cli::render::Envelope::ok("audit", data).to_json()
                );
            } else {
                print!("{}", audit::render_human(&out));
            }
            finish(out.exit_code as u8)
        }
        Some(Cmd::Rollback {
            target,
            plan_flag,
            list,
            yes,
            dry_run,
            json,
        }) => {
            let out = rollback::run_rollback(
                target.as_deref(),
                plan_flag.as_deref(),
                *list,
                cli.state_dir.as_deref(),
                None,
                *yes,
                *dry_run,
                *json,
                &runner,
            );
            if let Some(plans) = &out.plans {
                if *json {
                    let data = serde_json::json!({"plans": plans.iter().map(|(id, p, s, c)| serde_json::json!({"id": id, "profile": p, "status": s, "created_at": c})).collect::<Vec<_>>()});
                    println!(
                        "{}",
                        configctl_cli::render::Envelope::ok("rollback", data).to_json()
                    );
                } else {
                    print!("{}", rollback::render_human_list(plans));
                }
                return finish(0);
            }
            match (&out.report, &out.error) {
                (Some(rep), _) => {
                    if *json {
                        let data = serde_json::json!({"plan_id": rep.plan_id, "restored": rep.restored, "removed": rep.removed, "manual": rep.manual, "dry_run": rep.dry_run});
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::ok("rollback", data).to_json()
                        );
                    } else {
                        print!("{}", rollback::render_human(rep));
                    }
                    finish(0)
                }
                (None, Some(e)) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "rollback",
                                &rollback::error_message(e),
                                "see `configctl doctor`"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {}", rollback::error_message(e));
                    }
                    finish(out.exit_code as u8)
                }
                (None, None) => finish(1),
            }
        }
        Some(Cmd::Doctor { json }) => {
            let out = doctor::run_doctor(cli.state_dir.as_deref(), &runner);
            if *json {
                let data = serde_json::json!({
                    "os": out.os, "arch": out.arch, "distro": out.distro,
                    "package_manager": out.package_manager, "systemd_user": out.systemd_user,
                    "secret_backend": out.secret_backend, "state_dir": out.state_dir,
                    "state_ok": out.state_ok, "plans": out.plans,
                    "interrupted": out.interrupted.iter().map(|p| serde_json::json!({"plan_id": p.plan_id, "profile": p.profile, "status": p.status})).collect::<Vec<_>>(),
                });
                println!(
                    "{}",
                    configctl_cli::render::Envelope::ok("doctor", data).to_json()
                );
            } else {
                print!("{}", doctor::render_human(&out));
            }
            if out.state_ok {
                finish(0)
            } else {
                eprintln!("error: state directory unusable");
                finish(1)
            }
        }
        Some(Cmd::Init {
            profile,
            force,
            json,
        }) => {
            let out = init::run_init(profile.as_deref(), *force, None, cli.state_dir.as_deref());
            if let Some(e) = &out.error {
                if *json {
                    println!(
                        "{}",
                        configctl_cli::render::Envelope::error(
                            "init",
                            e,
                            "re-run with --force to overwrite"
                        )
                        .to_json()
                    );
                } else {
                    eprintln!("error: {e}");
                }
                return finish(out.exit_code as u8);
            }
            if *json {
                let data = serde_json::json!({
                    "config": out.config_path.to_string_lossy(),
                    "profiles": out.profiles_dir.to_string_lossy(),
                    "state": out.state_dir.to_string_lossy(),
                });
                println!(
                    "{}",
                    configctl_cli::render::Envelope::ok("init", data).to_json()
                );
            } else {
                print!("{}", init::render_human(&out));
            }
            finish(0)
        }
        Some(Cmd::Profile { cmd }) => match cmd {
            ProfileCmd::List { json } => match profile::run_list(None) {
                Err(e) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "profile list",
                                &e,
                                "run `configctl init`"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    finish(2)
                }
                Ok(infos) => {
                    if *json {
                        let data = serde_json::json!({"profiles": infos.iter().map(|i| serde_json::json!({"name": i.name, "path": i.path.to_string_lossy(), "schema_version": i.schema_version})).collect::<Vec<_>>()});
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::ok("profile list", data).to_json()
                        );
                    } else {
                        print!("{}", profile::render_list_human(&infos));
                    }
                    finish(0)
                }
            },
            ProfileCmd::Show { profile: p, json } => match profile::run_show(p) {
                Err(e) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "profile show",
                                &e,
                                "check the profile path"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    finish(2)
                }
                Ok(text) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::ok(
                                "profile show",
                                serde_json::json!({"profile": p, "document": text})
                            )
                            .to_json()
                        );
                    } else {
                        print!("{text}");
                    }
                    finish(0)
                }
            },
            ProfileCmd::Validate { profile: p, json } => {
                let errors = profile::run_validate(p);
                if *json {
                    let data = serde_json::json!({"profile": p, "valid": errors.is_empty(), "errors": errors});
                    println!(
                        "{}",
                        configctl_cli::render::Envelope::ok("profile validate", data).to_json()
                    );
                } else if errors.is_empty() {
                    println!("profile {p}: valid");
                } else {
                    eprintln!("profile {p}: invalid");
                    for e in &errors {
                        eprintln!("  - {e}");
                    }
                }
                if errors.is_empty() {
                    finish(0)
                } else {
                    finish(2)
                }
            }
            ProfileCmd::Migrate {
                profile: p,
                to,
                json,
            } => match profile::run_migrate(p, *to) {
                Err(e) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::error(
                                "profile migrate",
                                &e,
                                "only schema 1 is supported"
                            )
                            .to_json()
                        );
                    } else {
                        eprintln!("error: {e}");
                    }
                    finish(2)
                }
                Ok(msg) => {
                    if *json {
                        println!(
                            "{}",
                            configctl_cli::render::Envelope::ok(
                                "profile migrate",
                                serde_json::json!({"message": msg})
                            )
                            .to_json()
                        );
                    } else {
                        println!("{msg}");
                    }
                    finish(0)
                }
            },
        },
    };
    code
}
