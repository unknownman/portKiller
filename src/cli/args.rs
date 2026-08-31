//! Command-line interface definitions for `pk`.
//!
//! This module owns every user-facing string: binary identity, argument
//! definitions, help text, and usage examples. It contains **zero** parsing
//! logic for ports — ports are captured as raw strings and interpreted later
//! in [`crate::cli::port`].

use clap::Parser;

/// Inspect and free network ports. Shows you what's listening before you
/// decide what to do about it.
///
/// By default `pk` is a read-only inspector: `pk 3000` fetches and displays
/// exactly what is occupying port 3000 and terminates **nothing**. To actually
/// stop a process you must state your intent with `--kill` (graceful) or
/// `--force` (immediate).
#[derive(Debug, Clone, Parser)]
#[command(
    name = "pk",
    version,
    author,
    about = "Inspect ports. Kill with intent.",
    long_about = None,
    disable_help_subcommand = true,
    after_help = EXAMPLES,
)]
pub struct Cli {
    /// Ports to inspect, or kill. Accepts single ports (`3000`), multiple ports
    /// (`3000 8080`), and ranges (`9000-9005`). Mix and match freely.
    #[arg(
        value_name = "PORT",
        num_args = 1..,
        required = true,
        help = "One or more ports, or ranges like 9000-9005",
    )]
    pub ports: Vec<String>,

    /// Gracefully terminate the process(es) occupying the given port(s).
    ///
    /// Sends SIGTERM, waits briefly, verifies the port is actually released,
    /// and escalates to SIGKILL only if the process fails to exit on its own.
    ///
    /// Its conflict resolution is left to `--force`'s `overrides_with = "kill"`,
    /// so `pk -k -f 3000` lets `--force` (SIGKILL) win rather than erroring.
    #[arg(short, long)]
    pub kill: bool,

    /// Forcefully terminate immediately, skipping graceful shutdown.
    ///
    /// Sends SIGKILL directly, without the SIGTERM grace period. Useful on
    /// Windows (where SIGTERM is not available) and for stubborn or zombie
    /// processes.
    #[arg(short, long, visible_short_alias = 'y', overrides_with = "kill")]
    pub force: bool,

    /// Show what would be killed without sending any OS signals.
    ///
    /// Simulates the full kill sequence — displays the process(es) that would
    /// be terminated and which signal would be sent — but touches nothing.
    #[arg(long)]
    pub dry_run: bool,

    /// Emit structured JSON instead of a human-readable table.
    ///
    /// Designed for scripting, `jq`, and CI pipelines. Field names are stable;
    /// `killed` and `kill_signal` only describe the current invocation.
    #[arg(long)]
    pub json: bool,
}

/// Copy-pasteable usage examples shown at the bottom of `--help`.
const EXAMPLES: &str = "\
\
EXAMPLES:
    pk 3000                  Inspect port 3000 (read-only, nothing is killed)
    pk 3000 8080             Inspect multiple ports
    pk 9000-9005             Inspect a port range
    pk --kill 3000           Graceful kill: SIGTERM, verify, escalate to SIGKILL
    pk --force 5432          Immediate kill: straight to SIGKILL
    pk -y 5432               Same as --force (alias for skipping confirmations)
    pk --dry-run 3000        Show what --kill would do, without doing it
    pk --json 3000 | jq .    Machine-readable output for scripts and CI

Exit codes:
    0   All requested ports inspected and/or freed successfully
    1   Nothing to do — none of the requested ports were in use
    2   A kill failed (permission denied, port still occupied)
    3   Usage error or internal error
";

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli_app() {
        Cli::command().debug_assert();
    }
}
