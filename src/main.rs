//! Command-line entry point for `pk`.
//!
//! Phase 2 does not yet wire up the full inspect/kill pipeline; `main` is a
//! minimal stub that parses arguments and exits, so the crate compiles and the
//! parser test suites in `platform::*` can run.
//!
//! # Intermediate-state lint allowance
//!
//! The cross-platform API surface (`PlatformProvider`, `AppError`, the parser
//! functions) is intentionally fully implemented *before* the kill/render
//! phases that will consume it, so this crate currently trips `dead_code` on
//! public-but-unreferenced items. **Remove this `allow` once the orchestration
//! phase wires these in** — it must never be a permanent crutch.

#![allow(dead_code)]

mod cli;
mod error;
mod platform;
mod process;

use clap::Parser;
use cli::args::Cli;

fn main() {
    let _args = Cli::parse();
    // Pipeline wiring lands in a later phase.
}
