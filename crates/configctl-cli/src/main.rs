//! configctl binary entry point (P1: read-only discovery).

use clap::{Parser, Subcommand};
use configctl_cli::commands::scan;
use configctl_core::command::StdCommandRunner;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "configctl")]
#[command(about = "Linux-first environment manager (P1: read-only discovery)")]
#[command(version = "0.1.0")]
struct Cli {
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runner = StdCommandRunner::new();

    let code = match &cli.command {
        None => {
            eprintln!("configctl: no command given (try `configctl scan` or `configctl --help`)");
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
    };
    code
}
