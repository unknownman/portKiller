//! CLI argument definitions and parsing entry points.

pub mod args;
pub mod port;

use args::Cli;
use clap::Parser;

/// Top-level entry: parse the command line and hand off to the orchestrator.
/// The orchestrator logic itself arrives in a later phase; for now this merely
/// resolves the user's intent flags.
pub fn run() -> Cli {
    Cli::parse()
}
