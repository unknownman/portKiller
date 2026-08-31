//! Application orchestration: the end-to-end `pk` lifecycle.
//!
//! This module wires the (already-tested) pieces together:
//!
//! 1. **Resolve** ports (expand ranges) — [`crate::cli::port`]
//! 2. **Inspect** each port via [`PlatformProvider`]
//! 3. **Render** the collected view models and decide the exit code
//! 4. **Dry-run** annotates the STATUS column with what *would* happen
//! 5. **Confirm** graceful kills with a `[y/N]` prompt
//! 6. **Escalate** each process via [`terminate_one`] and verify
//! 7. **Report** via the render layer and map any failure to exit code 2
//!
//! All output — human and JSON alike — is produced by the pure [`crate::render`]
//! module, which only receives the view models built here. The orchestrator
//! decides *what* runs; rendering decides *how* it looks. All OS access is
//! injected via [`PlatformProvider`] / [`SignalSender`] so the lifecycle is
//! testable against mocks.

use crate::cli::args::Cli;
use crate::cli::port;
use crate::error::AppError;
use crate::kill::signal::SignalSender;
use crate::kill::{KillConfig, KillOutcome, terminate_one};
use crate::platform::PlatformProvider;
use crate::process::ProcessInfo;
use crate::process::Protocol;
use crate::process::enrich::ProcessEnricher;
use crate::render::{
    PortResult, ProcessStatus, RunMode, SignalKind, TableOptions, render_json, render_table,
};

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

    // 2. Inspect. Per-port failures are captured into the view model instead of
    //    aborting the run, so JSON mode can encode them and multi-port runs
    //    keep going past one broken port.
    let mut results = inspect_ports(runner.provider, &ports);

    // 3. Early terminal states.
    if results.iter().all(|r| r.is_free()) {
        emit(&results, cli.json);
        return exit::NOTHING_FOUND;
    }
    if results.iter().all(|r| r.is_error()) {
        emit(&results, cli.json);
        return exit::USAGE_OR_INTERNAL;
    }

    let kill_intent = cli.kill || cli.force;

    // Interactive kills are incompatible with JSON mode: the confirmation prompt
    // would block forever on stdin (hanging CI pipelines) and its `print!` to
    // stdout would corrupt the JSON stream that `jq` must parse. Reject the
    // combination up front; `--force` is the non-interactive, machine-friendly
    // path. This guard runs before `kill_intent` is ever checked.
    if cli.json && cli.kill && !cli.force {
        eprintln!(
            "error: Cannot use --kill interactively with --json. Use --force to confirm termination."
        );
        return exit::USAGE_OR_INTERNAL;
    }

    // 4. Dry-run: annotate every row with what *would* happen, touch nothing.
    if cli.dry_run {
        stamp_dry_run(&mut results, cli.force);
        emit_mode(&results, cli.json, RunMode::DryRun);
        return exit::OK;
    }

    // 5. Read-only mode: the rendered table is the whole story.
    if !kill_intent {
        emit_mode(&results, cli.json, RunMode::Inspect);
        return exit::OK;
    }

    // 6. Graceful kill needs confirmation. --force/-y skips the prompt, but
    //    still shows the affected processes in the pre-kill table below.
    if !cli.force {
        // Show the user exactly what is about to be killed *before* asking,
        // so the confirmation is never blind. Confirming mode prints the
        // standard table without the "inspect only" verdict footer. This
        // intermediate human step must never pollute JSON output, so it only
        // runs for the human view.
        if !cli.json {
            emit_mode(&results, cli.json, RunMode::Confirming);
        }
        if !confirm() {
            emit_mode(&results, cli.json, RunMode::Aborted);
            return exit::OK;
        }
    }

    // 7. Execute & verify, recording every outcome onto its row.
    let mut any_failed = false;
    for port_result in results.iter_mut().filter(|r| r.is_occupied()) {
        let port = port_result.port;
        for row in port_result.processes.iter_mut() {
            match terminate_one(
                port,
                &row.to_process_info(),
                cli.force,
                runner.signals,
                runner.provider,
                &runner.cfg,
            ) {
                Ok(KillOutcome::GracefulSuccess { .. }) => {
                    row.status = ProcessStatus::Terminated;
                    row.signal = Some(SignalKind::Sigterm);
                }
                Ok(KillOutcome::ForcefulSuccess { .. }) => {
                    row.status = ProcessStatus::Killed;
                    row.signal = Some(SignalKind::Sigkill);
                }
                Ok(KillOutcome::Failed { reason, .. }) => {
                    row.status = ProcessStatus::Failed;
                    row.error = Some(reason);
                    any_failed = true;
                }
                Err(e) => {
                    row.status = ProcessStatus::Failed;
                    row.error = Some(kill_error_text(&e, port, row.pid));
                    any_failed = true;
                }
            }
        }
    }

    emit_mode(&results, cli.json, RunMode::Kill);

    // 7. Exit code: 2 if any kill failed.
    if any_failed {
        exit::KILL_FAILED
    } else {
        exit::OK
    }
}

/// Inspect every port, building one render view per requested port. A port
/// that the OS refuses to inspect becomes an error-carrying view, never a
/// fatal panic.
///
/// This uses a lazy two-pass strategy: port discovery is cheap, so pass 1
/// inspects every port *without* touching `sysinfo`. Only if at least one port
/// is occupied does pass 2 build a single [`ProcessEnricher`] (one `sysinfo`
/// snapshot shared across the whole batch). A fully free / error-only run never
/// pays for the heavy OS scan at all. Input port order is preserved.
fn inspect_ports(provider: &dyn PlatformProvider, ports: &[u16]) -> Vec<PortResult> {
    let mut results = Vec::with_capacity(ports.len());
    // Occupied ports are remembered by their index in `results`, plus their raw
    // (unenriched) processes, so pass 2 can enrich exactly those in place.
    let mut occupied: Vec<(usize, u16, Vec<ProcessInfo>)> = Vec::new();

    // Pass 1: raw inspection. No sysinfo work happens here.
    for (idx, &port) in ports.iter().enumerate() {
        match provider.get_processes_on_port(port) {
            Ok(procs) if procs.is_empty() => results.push(PortResult::free(port)),
            Ok(procs) => {
                // Placeholder to preserve ordering; filled in with enriched data
                // only if pass 2 runs.
                results.push(PortResult::occupied(port, Vec::new()));
                occupied.push((idx, port, procs));
            }
            Err(e) => results.push(PortResult::inspection_error(
                port,
                Protocol::Tcp,
                e.to_string(),
            )),
        }
    }

    // Nothing is bound — there is nothing to enrich, so never build sysinfo.
    if occupied.is_empty() {
        return results;
    }

    // Pass 2: only now take the (single) sysinfo snapshot and enrich the raw
    // processes of every occupied port, writing each back to its slot.
    let mut enricher = ProcessEnricher::new();
    for (idx, port, procs) in occupied {
        results[idx] = PortResult::occupied(port, enricher.enrich_all(procs));
    }
    results
}

/// Mark every occupied process row with the signal that `--dry-run` _would_
/// have sent. No OS call is made.
fn stamp_dry_run(results: &mut [PortResult], force: bool) {
    let signal = SignalKind::from_force(force);
    for port in results.iter_mut().filter(|r| r.is_occupied()) {
        for row in &mut port.processes {
            row.status = ProcessStatus::DryRun;
            row.signal = Some(signal);
        }
    }
}

/// Normalise a signal-delivery error into an actionable, port-aware message.
/// The raw `AccessDenied` display says "port 0" because the signal layer does
/// not know its port; we supply that context here.
fn kill_error_text(err: &AppError, port: u16, pid: u32) -> String {
    match err {
        AppError::AccessDenied { .. } => format!(
            "permission denied signalling PID {pid} on port {port}; \
             try running `pk` with sudo"
        ),
        other => other.to_string(),
    }
}

/// Print either the JSON document or the default (inspect-mode) human view.
fn emit(results: &[PortResult], json: bool) {
    emit_mode(results, json, RunMode::Inspect);
}

/// Print either the JSON document or the human view for a given run mode.
///
/// JSON output is mode-agnostic: the per-row `status`/`signal` fields already
/// describe the invocation, so `--json | jq` never sees human text mixed in.
fn emit_mode(results: &[PortResult], json: bool, mode: RunMode) {
    if json {
        println!("{}", render_json(results));
    } else {
        print!("{}", render_table(results, &TableOptions::new(mode)));
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
    use crate::process::ProcessInfo;
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
        fn is_process_gone_from_port(
            &self,
            _port: u16,
            _target_pid: u32,
        ) -> Result<bool, AppError> {
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
    fn json_kill_without_force_exits_with_error() {
        let provider = FakeProvider {
            processes: vec![ProcessInfo::bare(1234, "node".into())],
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let signals = Recorder {
            calls: calls.clone(),
        };
        // --json + --kill (no --force) must be rejected up front, so confirm() is
        // never invoked and no signal is ever sent — even if the user would say
        // "yes".
        let mut args = cli(&["3000"], true, false, false);
        args.json = true;
        let code = run(&runner(&provider, &signals), &args, || true);
        assert_eq!(code, exit::USAGE_OR_INTERNAL);
        assert!(
            calls.lock().unwrap().is_empty(),
            "rejected interactive --json kill must not send any signals"
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

    #[test]
    fn kill_failure_maps_to_exit_2() {
        // A provider whose port never frees makes every kill end in
        // KillOutcome::Failed, which must surface as exit code 2.
        struct Stubborn {
            processes: Vec<ProcessInfo>,
        }
        impl PlatformProvider for Stubborn {
            fn get_processes_on_port(&self, _port: u16) -> Result<Vec<ProcessInfo>, AppError> {
                Ok(self.processes.clone())
            }
            fn is_port_free(&self, _port: u16) -> Result<bool, AppError> {
                Ok(false)
            }
        }
        let provider = Stubborn {
            processes: vec![ProcessInfo::bare(1234, "node".into())],
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let signals = Recorder {
            calls: calls.clone(),
        };
        let code = run(
            &runner(&provider, &signals),
            &cli(&["3000"], true, false, false),
            || true,
        );
        assert_eq!(code, exit::KILL_FAILED);
        assert!(!calls.lock().unwrap().is_empty());
    }
}
