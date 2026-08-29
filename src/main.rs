//! Command-line entry point for `pk`.
//!
//! Parses arguments, wires the real platform provider and signal sender into
//! the application lifecycle, and maps the result to a process exit code.
//!
//! # `dead_code` allowance
//!
//! This crate ships complete per-OS implementations selected at compile time by
//! `#[cfg(target_os)]`. On any single host the *other* platforms' modules are
//! legitimate live code that no call site reaches, and several `AppError`
//! variants are constructed only from those dormant modules. **Keep this
//! allowance scoped and intentional**: it reflects genuinely cross-platform code
//! that a single build environment cannot exercise, not disposable scaffolding.

#![allow(dead_code)]

mod app;
mod cli;
mod error;
mod kill;
mod platform;
mod process;

use app::Runner;
use clap::Parser;
use cli::args::Cli;
use kill::KillConfig;
use kill::signal::OsSignals;

fn main() {
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
