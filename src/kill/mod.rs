//! Kill orchestration and the escalation loop.
//!
//! # Safety posture
//!
//! Termination is destructive, so this module is built around the escalation
//! principle: **try the gentlest step, verify the claimed outcome, escalate
//! only when forced, and never claim success without proof.**
//!
//! Every process termination path runs through the injectable
//! [`SignalSender`] and [`PlatformProvider`] seams, so the logic here is fully
//! unit-testable against mocks. **No test in this crate ever signals a real
//! PID.**
//!
//! # Trust through verification
//!
//! A kill is only reported as *Success* after
//! [`PlatformProvider::is_process_gone_from_port`] confirms the target PID has
//! actually dropped off the port. Verification is per-process (not per-port), so
//! on a shared port killing one worker succeeds even while a sibling still
//! listens. If a graceful `SIGTERM` is ignored, we escalate to `SIGKILL` (unless
//! `--force` skipped straight there). If even `SIGKILL` fails to dislodge the
//! target, the outcome is [`KillOutcome::Failed`] — reported honestly rather
//! than assumed away.

pub mod signal;

use std::time::{Duration, Instant};

use crate::error::AppError;
use crate::platform::PlatformProvider;
use crate::process::ProcessInfo;

use signal::{Signal, SignalSender};

/// Tunable timing knobs for the escalation loop.
///
/// Kept as a struct so tests can shrink every delay toward zero, making the
/// polling logic deterministic and instant without adding a fake-clock seam.
#[derive(Debug, Clone)]
pub struct KillConfig {
    /// Interval between `is_port_free` polls.
    pub poll_interval: Duration,
    /// How long to wait for a graceful `SIGTERM` to free the port before
    /// escalating to `SIGKILL`.
    pub grace_timeout: Duration,
    /// How long to wait after `SIGKILL` before declaring failure.
    pub final_verify: Duration,
}

impl Default for KillConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(100),
            grace_timeout: Duration::from_secs(2),
            final_verify: Duration::from_secs(1),
        }
    }
}

/// The structured result of attempting to free one port by terminating one
/// process. Always surfaced to the user; never silently swallowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillOutcome {
    /// Port freed after a graceful `SIGTERM`. (Never produced on Windows, where
    /// both signals collapse to forced termination.)
    GracefulSuccess { port: u16, pid: u32 },
    /// Port freed after `SIGKILL`.
    ForcefulSuccess { port: u16, pid: u32 },
    /// The process was signalled but the port refused to free — zombie/stuck,
    /// or owned by a supervisor that respawns it.
    Failed { port: u16, pid: u32, reason: String },
}

impl KillOutcome {
    /// True when the target process was verified gone from the port, regardless
    /// of which signal was used.
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            KillOutcome::GracefulSuccess { .. } | KillOutcome::ForcefulSuccess { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Escalation loop
// ---------------------------------------------------------------------------

/// Terminate one process occupying `port`, escalating as necessary, and verify
/// *that specific process* is gone before returning success.
///
/// Verification is per-process, not per-port: on a shared port (e.g.
/// `SO_REUSEPORT` workers) killing one PID must not be reported as a failure
/// merely because a sibling still listens. Success is claimed once the target
/// PID has dropped off the port.
///
/// * `force == true`: jump straight to [`Signal::Kill`].
/// * `force == false`: send [`Signal::Terminate`], wait up to `grace_timeout`,
///   and only escalate to [`Signal::Kill`] if the target is still present.
///
/// No OS call is made here directly — both `signals` and `provider` are injected
/// traits, which is what allows the loop to be tested in isolation.
pub fn terminate_one(
    port: u16,
    process: &ProcessInfo,
    force: bool,
    signals: &dyn SignalSender,
    provider: &dyn PlatformProvider,
    cfg: &KillConfig,
) -> Result<KillOutcome, AppError> {
    let pid = process.pid;

    if force {
        signals.send(pid, Signal::Kill)?;
        return if poll_until_gone(port, pid, provider, cfg.final_verify, cfg) {
            Ok(KillOutcome::ForcefulSuccess { port, pid })
        } else {
            Ok(KillOutcome::Failed {
                port,
                pid,
                reason: format!(
                    "PID {pid} still bound to port {port} after SIGKILL (zombie/stuck or restarted)"
                ),
            })
        };
    }

    // Graceful attempt.
    signals.send(pid, Signal::Terminate)?;
    if poll_until_gone(port, pid, provider, cfg.grace_timeout, cfg) {
        return Ok(KillOutcome::GracefulSuccess { port, pid });
    }

    // SIGTERM ignored or too slow — escalate.
    signals.send(pid, Signal::Kill)?;
    if poll_until_gone(port, pid, provider, cfg.final_verify, cfg) {
        Ok(KillOutcome::ForcefulSuccess { port, pid })
    } else {
        Ok(KillOutcome::Failed {
            port,
            pid,
            reason: format!(
                "PID {pid} still bound to port {port} after SIGTERM→SIGKILL (zombie/stuck or restarted)"
            ),
        })
    }
}

/// Poll `provider.is_process_gone_from_port(port, target_pid)` every
/// `cfg.poll_interval` until `timeout` elapses. Returns true as soon as the
/// target PID drops off the port.
fn poll_until_gone(
    port: u16,
    target_pid: u32,
    provider: &dyn PlatformProvider,
    timeout: Duration,
    cfg: &KillConfig,
) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        // Transient inspection errors are treated as "still present"; the
        // caller's final verdict decides, and we never over-report success.
        if let Ok(true) = provider.is_process_gone_from_port(port, target_pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(cfg.poll_interval);
    }
}

// ---------------------------------------------------------------------------
// Tests (mocked — no real PIDs are ever signalled)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::ProcessInfo;
    use std::sync::{Arc, Mutex};

    /// Records every signal it is asked to send; never touches the OS.
    struct MockSignals {
        calls: Arc<Mutex<Vec<(u32, Signal)>>>,
        /// When true, `send` fails.
        fail: bool,
    }

    impl MockSignals {
        fn new(calls: Arc<Mutex<Vec<(u32, Signal)>>>) -> Self {
            Self { calls, fail: false }
        }
        fn failing(calls: Arc<Mutex<Vec<(u32, Signal)>>>) -> Self {
            Self { calls, fail: true }
        }
    }

    impl SignalSender for MockSignals {
        fn send(&self, pid: u32, signal: Signal) -> Result<(), AppError> {
            self.calls.lock().unwrap().push((pid, signal));
            if self.fail {
                Err(AppError::kill_failed(format!(
                    "mock refusal to signal PID {pid}"
                )))
            } else {
                Ok(())
            }
        }
    }

    /// When a mock port should be reported as free, driven off the shared
    /// signal log so the two polling phases (graceful vs. force) are
    /// distinguishable deterministically — no wall-clock dependence.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FreeWhen {
        /// The port frees as soon as `SIGTERM` has been sent (graceful works).
        Sigterm,
        /// The port frees as soon as `SIGKILL` has been sent (graceful alone
        /// fails, but escalation succeeds).
        Sigkill,
        /// The port never frees (even a force kill fails).
        Never,
    }

    /// A `PlatformProvider` whose `is_port_free` is driven by the shared signal
    /// log. Mirrors reality: a port becomes free once a strong enough signal has
    /// been delivered to its owner.
    struct MockProvider {
        free_when: FreeWhen,
        signals: Arc<Mutex<Vec<(u32, Signal)>>>,
    }

    impl PlatformProvider for MockProvider {
        fn get_processes_on_port(&self, _port: u16) -> Result<Vec<ProcessInfo>, AppError> {
            unreachable!("tests drive termination directly")
        }
        fn is_port_free(&self, _port: u16) -> Result<bool, AppError> {
            self.target_gone()
        }
        fn is_process_gone_from_port(
            &self,
            _port: u16,
            _target_pid: u32,
        ) -> Result<bool, AppError> {
            self.target_gone()
        }
    }

    impl MockProvider {
        /// Whether the signal-driven mock has progressed far enough to consider
        /// the (single, unnamed) target gone — shared by both free checks.
        fn target_gone(&self) -> Result<bool, AppError> {
            let sent = self.signals.lock().unwrap();
            Ok(match self.free_when {
                FreeWhen::Sigterm => sent.iter().any(|&(_, s)| s == Signal::Terminate),
                FreeWhen::Sigkill => sent.iter().any(|&(_, s)| s == Signal::Kill),
                FreeWhen::Never => false,
            })
        }
    }

    fn proc(pid: u32) -> ProcessInfo {
        ProcessInfo::bare(pid, "test".into())
    }

    fn recording(port: u16, force: bool, free_when: FreeWhen) -> (KillOutcome, Vec<(u32, Signal)>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let outcome = terminate_one(
            port,
            &proc(1234),
            force,
            &MockSignals::new(calls.clone()),
            &MockProvider {
                free_when,
                signals: calls.clone(),
            },
            &KillConfig {
                poll_interval: Duration::from_millis(1),
                grace_timeout: Duration::from_millis(5),
                final_verify: Duration::from_millis(5),
            },
        )
        .unwrap();
        let calls = calls.lock().unwrap().clone();
        (outcome, calls)
    }

    fn signal_sequence(calls: &[(u32, Signal)]) -> Vec<Signal> {
        calls.iter().map(|&(_, s)| s).collect()
    }

    // 1. --force jumps straight to SIGKILL (no SIGTERM first).
    #[test]
    fn force_jumps_straight_to_sigkill() {
        let (outcome, calls) = recording(3000, true, FreeWhen::Sigkill);
        assert_eq!(signal_sequence(&calls), vec![Signal::Kill]);
        assert_eq!(
            outcome,
            KillOutcome::ForcefulSuccess {
                port: 3000,
                pid: 1234
            }
        );
    }

    // 2. A successful SIGTERM prevents SIGKILL.
    #[test]
    fn successful_sigterm_prevents_sigkill() {
        let (outcome, calls) = recording(3000, false, FreeWhen::Sigterm);
        assert_eq!(signal_sequence(&calls), vec![Signal::Terminate]);
        assert_eq!(
            outcome,
            KillOutcome::GracefulSuccess {
                port: 3000,
                pid: 1234
            }
        );
    }

    // 3. A failed (ignored) SIGTERM escalates to SIGKILL, which frees the port.
    #[test]
    fn failed_sigterm_escalates_to_sigkill() {
        let (outcome, calls) = recording(3000, false, FreeWhen::Sigkill);
        assert_eq!(
            signal_sequence(&calls),
            vec![Signal::Terminate, Signal::Kill]
        );
        assert_eq!(
            outcome,
            KillOutcome::ForcefulSuccess {
                port: 3000,
                pid: 1234
            }
        );
    }

    // 4. A failed SIGKILL returns a failure outcome.
    #[test]
    fn failed_sigkill_returns_error_outcome() {
        // Port never frees even after the forced kill.
        let (outcome, calls) = recording(3000, true, FreeWhen::Never);
        assert_eq!(signal_sequence(&calls), vec![Signal::Kill]);
        match outcome {
            KillOutcome::Failed { port, pid, .. } => {
                assert_eq!(port, 3000);
                assert_eq!(pid, 1234);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    // A failed SIGTERM where even an escalated SIGKILL can't free the port is
    // Failed, and both signals were attempted.
    #[test]
    fn failed_sigterm_then_failed_sigkill_is_failed_with_both_signals() {
        let (outcome, calls) = recording(3000, false, FreeWhen::Never);
        assert_eq!(
            signal_sequence(&calls),
            vec![Signal::Terminate, Signal::Kill]
        );
        assert!(matches!(outcome, KillOutcome::Failed { .. }));
    }

    // When signal delivery itself fails (e.g. permission), the error propagates.
    #[test]
    fn signal_delivery_error_propagates() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let res = terminate_one(
            3000,
            &proc(1234),
            true,
            &MockSignals::failing(calls.clone()),
            &MockProvider {
                free_when: FreeWhen::Never,
                signals: calls.clone(),
            },
            &KillConfig::default(),
        );
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("mock refusal"));
    }

    #[test]
    fn outcomes_classify_success_properly() {
        assert!(KillOutcome::GracefulSuccess { port: 1, pid: 1 }.is_success());
        assert!(KillOutcome::ForcefulSuccess { port: 1, pid: 1 }.is_success());
        assert!(
            !KillOutcome::Failed {
                port: 1,
                pid: 1,
                reason: String::new()
            }
            .is_success()
        );
    }

    /// A signal sender that removes a pid from the shared occupant set when it
    /// is signalled — modelling a worker that actually dies on signal.
    struct KillOnSignal {
        occupants: Arc<Mutex<Vec<u32>>>,
    }
    impl SignalSender for KillOnSignal {
        fn send(&self, pid: u32, _signal: Signal) -> Result<(), AppError> {
            self.occupants.lock().unwrap().retain(|&p| p != pid);
            Ok(())
        }
    }

    /// A shared-port provider: tracks which PIDs currently occupy the port and
    /// reports the target gone iff *that pid* dropped off — never because the
    /// whole port freed. This mirrors a real `SO_REUSEPORT` port where killing
    /// PID 1 must not be reported failed while PID 2 still listens.
    struct SharedPortProvider {
        occupants: Arc<Mutex<Vec<u32>>>,
    }
    impl PlatformProvider for SharedPortProvider {
        fn get_processes_on_port(&self, _port: u16) -> Result<Vec<ProcessInfo>, AppError> {
            Ok(self
                .occupants
                .lock()
                .unwrap()
                .iter()
                .map(|&p| ProcessInfo::bare(p, "worker".into()))
                .collect())
        }
        fn is_port_free(&self, _port: u16) -> Result<bool, AppError> {
            Ok(self.occupants.lock().unwrap().is_empty())
        }
        fn is_process_gone_from_port(&self, _port: u16, target_pid: u32) -> Result<bool, AppError> {
            Ok(!self.occupants.lock().unwrap().contains(&target_pid))
        }
    }

    // Regression: two SO_REUSEPORT workers share one port. Killing worker 1234
    // must be reported a success once *1234* drops off — the port being still
    // occupied by worker 1235 must NOT turn this into KillOutcome::Failed.
    #[test]
    fn killing_one_worker_on_shared_port_succeeds() {
        let occupants = Arc::new(Mutex::new(vec![1234u32, 1235u32]));
        let outcome = terminate_one(
            3000,
            &proc(1234),
            true, // force (or the escalation path — same verification)
            &KillOnSignal {
                occupants: occupants.clone(),
            },
            &SharedPortProvider {
                occupants: occupants.clone(),
            },
            &KillConfig {
                poll_interval: Duration::from_millis(1),
                grace_timeout: Duration::from_millis(5),
                final_verify: Duration::from_millis(5),
            },
        )
        .unwrap();

        assert_eq!(
            outcome,
            KillOutcome::ForcefulSuccess {
                port: 3000,
                pid: 1234
            },
            "killing one SO_REUSEPORT worker must succeed even though the port \
             is still held by a sibling"
        );

        // The target worker is gone...
        assert_eq!(*occupants.lock().unwrap(), vec![1235u32]);
        // ...but the port itself is still NOT free (the sibling remains). This
        // is the crux: the old global `is_port_free` check would have misread
        // the still-busy port as a failed kill of PID 1234.
        let provider = SharedPortProvider {
            occupants: occupants.clone(),
        };
        assert!(!provider.is_port_free(3000).unwrap());
        assert!(outcome.is_success());
    }
}
