//! Application orchestration: the end-to-end `pk` lifecycle.
//!
//! This module wires the (already-tested) pieces together:
//!
//! 1. **Resolve** ports (expand ranges) — [`crate::cli::port`]
//! 2. **Inspect** each port via [`PlatformProvider`]
//! 3. **Bail early** if nothing is listening (exit 1)
//! 4. **Dry-run** summary with no OS signals (exit 0)
//! 5. **Confirm** graceful kills with a `[y/N]` prompt
//! 6. **Escalate** each process via [`terminate_one`] and verify
//! 7. **Report** and map any failure to exit code 2
//!
//! Rendering here is deliberately minimal (full table/JSON rendering lands in a
//! later phase). All OS access is injected via [`PlatformProvider`] /
//! [`SignalSender`] so the lifecycle is testable against mocks.

use crate::cli::args::Cli;
use crate::cli::port;
use crate::error::AppError;
use crate::kill::signal::SignalSender;
use crate::kill::{KillConfig, KillOutcome, terminate_one};
use crate::platform::PlatformProvider;
use crate::process::ProcessInfo;

/// Injected dependencies for the execution lifecycle.
pub struct Runner<'a> {
    pub provider: &'a dyn PlatformProvider,
    pub signals: &'a dyn SignalSender,
    pub cfg: KillConfig,
}

/// Exit codes, matching the README's documented contract.
pub mod exit {
    pub const OK: i32 = 0;
    pub const NOTHING_FOUND: i32 = 1;
    pub const KILL_FAILED: i32 = 2;
    pub const USAGE_OR_INTERNAL: i32 = 3;
}

/// Run the full lifecycle and return the process exit code.
///
/// `confirm` is injected so the confirmation prompt is testable; the real CLI
/// passes [`prompt_confirm`].
pub fn run(runner: &Runner, cli: &Cli, mut confirm: impl FnMut() -> bool) -> i32 {
    let ports = match port::resolve_ports(&cli.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return exit::USAGE_OR_INTERNAL;
        }
    };

    // 2. Inspect
    let occupied: Vec<(u16, ProcessInfo)> = match inspect_ports(runner.provider, &ports) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("error: {e}");
            return exit::USAGE_OR_INTERNAL;
        }
    };

    // 3. Bail early
    if occupied.is_empty() {
        println!("No processes found listening on requested ports.");
        return exit::NOTHING_FOUND;
    }

    let kill_intent = cli.kill || cli.force;

    // 4. Dry-run: report what *would* happen, touch nothing.
    if cli.dry_run {
        summarize_dry_run(&occupied, cli.force);
        return exit::OK;
    }

    // 5. Confirm graceful kills (--force/-y skips the prompt).
    if kill_intent && !cli.force && !confirm() {
        println!("Aborted. No processes were terminated.");
        return exit::OK;
    }

    if !kill_intent {
        // Inspect-only mode: nothing to do beyond what we already showed.
        return exit::OK;
    }

    // 6. Execute & verify
    let mut any_failed = false;
    for (port, process) in &occupied {
        match terminate_one(
            *port,
            process,
            cli.force,
            runner.signals,
            runner.provider,
            &runner.cfg,
        ) {
            Ok(outcome) => {
                report_outcome(&outcome);
                if !outcome.is_success() {
                    any_failed = true;
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                any_failed = true;
            }
        }
    }

    // 7. Exit code: 2 if any kill failed.
    if any_failed {
        exit::KILL_FAILED
    } else {
        exit::OK
    }
}

/// Inspect every port and collect the `(port, process)` pairs in use.
fn inspect_ports(
    provider: &dyn PlatformProvider,
    ports: &[u16],
) -> Result<Vec<(u16, ProcessInfo)>, AppError> {
    let mut occupied = Vec::new();
    for &port in ports {
        let procs = provider.get_processes_on_port(port)?;
        for p in procs {
            occupied.push((port, p));
        }
    }
    Ok(occupied)
}

fn summarize_dry_run(occupied: &[(u16, ProcessInfo)], force: bool) {
    let signal = if force { "SIGKILL" } else { "SIGTERM" };
    println!("Dry run — no signals sent. Would terminate with {signal}:");
    for (port, p) in occupied {
        println!("  port {port} → PID {} ({})", p.pid, p.name);
    }
}

fn report_outcome(outcome: &KillOutcome) {
    match outcome {
        KillOutcome::GracefulSuccess { port, pid } => {
            println!("✅ Port {port} freed (PID {pid} terminated gracefully)");
        }
        KillOutcome::ForcefulSuccess { port, pid } => {
            println!("✅ Port {port} freed (PID {pid} terminated forcefully)");
        }
        KillOutcome::Failed { port, pid, reason } => {
            eprintln!("❌ Port {port} NOT freed (PID {pid}): {reason}");
        }
    }
}

/// Real confirmation prompt reading from stdin. Defaults to **no**.
pub fn prompt_confirm() -> bool {
    use std::io::Write;
    print!("Proceed with termination? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    let answer = line.trim().to_ascii_lowercase();
    answer == "y" || answer == "yes"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kill::signal::{Signal, SignalSender};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn cli(ports: &[&str], kill: bool, force: bool, dry_run: bool) -> Cli {
        Cli {
            ports: ports.iter().map(|s| s.to_string()).collect(),
            kill,
            force,
            dry_run,
            json: false,
        }
    }

    /// Records signals (so tests assert nothing was sent where none should be).
    struct Recorder {
        calls: Arc<Mutex<Vec<(u32, Signal)>>>,
    }
    impl SignalSender for Recorder {
        fn send(&self, pid: u32, signal: Signal) -> Result<(), AppError> {
            self.calls.lock().unwrap().push((pid, signal));
            Ok(())
        }
    }

    /// Scripted provider: returns the configured processes, and `is_port_free`
    /// always reports free (so any kill verifies successfully).
    struct FakeProvider {
        processes: Vec<ProcessInfo>,
    }
    impl PlatformProvider for FakeProvider {
        fn get_processes_on_port(&self, _port: u16) -> Result<Vec<ProcessInfo>, AppError> {
            Ok(self.processes.clone())
        }
        fn is_port_free(&self, _port: u16) -> Result<bool, AppError> {
            Ok(true)
        }
    }

    fn runner<'a>(provider: &'a dyn PlatformProvider, signals: &'a dyn SignalSender) -> Runner<'a> {
        Runner {
            provider,
            signals,
            cfg: KillConfig {
                poll_interval: Duration::from_millis(1),
                grace_timeout: Duration::from_millis(5),
                final_verify: Duration::from_millis(5),
            },
        }
    }

    #[test]
    fn nothing_found_exits_1() {
        let provider = FakeProvider { processes: vec![] };
        let signals = Recorder {
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let code = run(
            &runner(&provider, &signals),
            &cli(&["3000"], false, false, false),
            || false,
        );
        assert_eq!(code, exit::NOTHING_FOUND);
    }

    #[test]
    fn dry_run_sends_no_signals_and_exits_0() {
        let provider = FakeProvider {
            processes: vec![ProcessInfo::bare(1234, "node".into())],
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let signals = Recorder {
            calls: calls.clone(),
        };
        let code = run(
            &runner(&provider, &signals),
            &cli(&["3000"], true, false, true),
            || true,
        );
        assert_eq!(code, exit::OK);
        assert!(
            calls.lock().unwrap().is_empty(),
            "dry-run must not send any signals"
        );
    }

    #[test]
    fn graceful_kill_aborted_on_declined_confirmation() {
        let provider = FakeProvider {
            processes: vec![ProcessInfo::bare(1234, "node".into())],
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let signals = Recorder {
            calls: calls.clone(),
        };
        let code = run(
            &runner(&provider, &signals),
            &cli(&["3000"], true, false, false),
            || false, // user declines
        );
        assert_eq!(code, exit::OK);
        assert!(
            calls.lock().unwrap().is_empty(),
            "declined confirmation must not send signals"
        );
    }

    #[test]
    fn force_kill_skips_confirmation_and_sends_sigkill() {
        let provider = FakeProvider {
            processes: vec![ProcessInfo::bare(1234, "node".into())],
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let signals = Recorder {
            calls: calls.clone(),
        };
        // confirm() would return `false`, but --force must not consult it.
        let code = run(
            &runner(&provider, &signals),
            &cli(&["3000"], false, true, false),
            || false,
        );
        assert_eq!(code, exit::OK);
        assert_eq!(*calls.lock().unwrap(), vec![(1234, Signal::Kill)]);
    }
}
