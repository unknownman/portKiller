//! Cross-platform process signal dispatch.
//!
//! # Abstraction
//!
//! POSIX platforms (`libc`) expose real signals; Windows has none. We hide that
//! difference behind a single [`SignalSender`] trait so the escalation
//! orchestrator in [`super`] is platform-agnostic **and** mockable — tests
//! substitute a fake [`SignalSender`] that records calls instead of touching
//! real PIDs.
//!
//! # Windows `SIGTERM` quirk
//!
//! Windows has no POSIX `SIGTERM`/`SIGKILL`. Both [`send_sigterm`] and
//! [`send_sigkill`] translate to `TerminateProcess`, i.e. an **immediate, forced
//! termination**. This is honest: there is no side-effect-free "graceful"
//! signal to fake, and pretending otherwise would violate our trust principle.
//! The CLI surfaces this in its help text (`--force` is the recommended path on
//! Windows) and the graceful/forceful distinction collapses to a single call.

use crate::error::AppError;

/// The termination "strength" we intend to apply.
///
/// On POSIX this maps to `SIGTERM` vs `SIGKILL`. On Windows both map to
/// [`TerminateProcess`]; callers should treat [`Signal::Kill`] as the truthful
/// description of what happens there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Graceful request to terminate (`SIGTERM`). The process may finish
    /// cleanly or ignore this.
    Terminate,
    /// Forced termination (`SIGKILL` / `TerminateProcess`). Cannot be caught or
    /// ignored by the target.
    Kill,
}

impl Signal {
    /// The POSIX signal number, for platforms that have one.
    #[cfg(unix)]
    fn unix_num(self) -> i32 {
        match self {
            Signal::Terminate => libc::SIGTERM,
            Signal::Kill => libc::SIGKILL,
        }
    }
}

/// An abstraction over "send a signal to a PID".
///
/// This is the **single** seam through which the orchestrator terminates
/// processes, which is what makes the escalation loop fully unit-testable
/// without ever signalling a real PID.
pub trait SignalSender {
    /// Send `signal` to `pid`.
    ///
    /// Returns `Ok(())` when the signal was accepted *or* the target was
    /// already gone (a process that vanished is, from a freeing-the-port
    /// standpoint, already handled — there is nothing left to signal).
    fn send(&self, pid: u32, signal: Signal) -> Result<(), AppError>;
}

/// Convenience free functions that use the real OS sender.
pub fn send_sigterm(pid: u32) -> Result<(), AppError> {
    OsSignals.send(pid, Signal::Terminate)
}

pub fn send_sigkill(pid: u32) -> Result<(), AppError> {
    OsSignals.send(pid, Signal::Kill)
}

// ---------------------------------------------------------------------------
// POSIX (Linux, macOS) implementation — libc::kill
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub struct OsSignals;

#[cfg(unix)]
impl SignalSender for OsSignals {
    fn send(&self, pid: u32, signal: Signal) -> Result<(), AppError> {
        // Safety guard: POSIX signalling is a broadcast footgun.
        //   * pid == 0 signals the entire process group.
        //   * casting pid to the signed `pid_t` wraps values above i32::MAX
        //     into negatives (e.g. u32::MAX -> -1), and kill(-1) signals every
        //     process the user may terminate.
        // A single discovery bug must never be able to wipe the user's session,
        // so reject these PIDs outright before the unsafe call.
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(AppError::internal(format!(
                "refusing to signal PID {pid}: invalid PID (would target a process group or \
                 every process)"
            )));
        }

        let ret = unsafe { libc::kill(pid as libc::pid_t, signal.unix_num()) };
        if ret == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // No such process: already gone. Nothing left to signal.
            Some(libc::ESRCH) => Ok(()),
            // Permission denied: the process belongs to another user/root.
            Some(libc::EPERM) => Err(AppError::AccessDenied {
                port: 0, // port not known at this layer; caller supplies context
            }),
            _ => Err(AppError::kill_failed(format!(
                "could not signal PID {pid}: {err}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Windows implementation — TerminateProcess
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub struct OsSignals;

#[cfg(windows)]
impl SignalSender for OsSignals {
    fn send(&self, pid: u32, _signal: Signal) -> Result<(), AppError> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_TERMINATE, TerminateProcess,
        };

        // SAFETY: we request only PROCESS_TERMINATE rights, which is the
        // minimal set needed to call TerminateProcess. The handle is closed on
        // every path via CloseHandle below.
        let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() {
            return Err(AppError::kill_failed(format!(
                "could not open PID {pid} for termination (is it running / do you have permission?)"
            )));
        }

        // SAFETY: `handle` is a valid open process handle with PROCESS_TERMINATE
        // permission (just verfified). Exit code 1 is arbitrary — the process
        // dies regardless.
        let ok = unsafe { TerminateProcess(handle, 1) };
        // SAFETY: closing a handle we own.
        unsafe { CloseHandle(handle) };

        if ok != 0 {
            Ok(())
        } else {
            Err(AppError::kill_failed(format!(
                "could not terminate PID {pid}: {}",
                std::io::Error::last_os_error()
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// PID 0 and any PID that wraps to a negative `pid_t` (e.g. u32::MAX -> -1)
    /// would make `libc::kill` broadcast to a process group or every process.
    /// These must be rejected up front — `Internal` error, no signal delivered,
    /// no panic.
    #[test]
    fn invalid_pids_are_rejected_before_kill() {
        let subject = OsSignals;
        for bad_pid in [0u32, u32::MAX] {
            let result = subject.send(bad_pid, Signal::Terminate);
            let err = match result {
                Ok(()) => panic!("expected PID {bad_pid} to be rejected"),
                Err(e) => e,
            };
            assert!(
                matches!(err, AppError::Internal { .. }),
                "PID {bad_pid} should produce AppError::Internal, got: {err:?}"
            );
            assert!(
                err.to_string().contains("invalid PID"),
                "message should explain the guard: {err}"
            );
        }
    }
}
