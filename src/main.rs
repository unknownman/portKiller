//! Command-line entry point for `pk`.
//!
//! Parses arguments, wires the real platform provider and signal sender into
//! the application lifecycle, and maps the result to a process exit code.
//!
//! # Dormant platform code
//!
//! This crate ships complete per-OS implementations selected at compile time by
//! `#[cfg(target_os)]`. On any single host the *other* platforms' modules are
//! legitimate live code that no call site reaches. Those items carry narrowly
//! scoped `#[cfg_attr(not(target_os = ...), allow(dead_code))]` (or platform
//! `#[allow(dead_code)]`) attributes directly above them, rather than a crate-
//! wide suppression, so genuinely unused code elsewhere is still caught.

mod app;
mod cli;
mod error;
mod kill;
mod platform;
mod process;
mod render;

use app::Runner;
use clap::Parser;
use cli::args::Cli;
use kill::KillConfig;
use kill::signal::OsSignals;

fn main() {
    // Enable ANSI rendering on Windows `cmd.exe`/conhost, which does not opt in
    // to virtual terminal processing by default. (`set_virtual_terminal` is a
    // Windows-only API.)
    #[cfg(windows)]
    let _ = colored::control::set_virtual_terminal(true);
    let cli = Cli::parse();
    let exit_code = real_run(&cli);
    std::process::exit(exit_code);
}

/// Run against the real OS. Separated from `main` so the wiring is obvious and
/// the lifecycle itself (in `app::run`) remains mock-testable.
fn real_run(cli: &Cli) -> i32 {
    let provider = platform::default_provider();
    let signals = OsSignals;
    let runner = Runner {
        provider: &provider,
        signals: &signals,
        cfg: KillConfig::default(),
    };
    app::run(&runner, cli, app::prompt_confirm)
}
