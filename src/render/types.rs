//! Presentation-layer view models.
//!
//! These types are the **only** inputs the renderers understand. The
//! orchestrator (`crate::app`) builds them from the Phase-2/3 domain models
//! (`ProcessInfo`, `KillOutcome`) and hands them to [`crate::render::render_table`]
//! / [`crate::render::render_json`]. Like the domain models, they are dumb data:
//! they know how to be cloned, compared, and serialized — never how to touch
//! the OS or draw themselves.

use serde::Serialize;

use crate::process::{ProcessInfo, Protocol};

/// The signal that was (or would have been) delivered to a process.
///
/// A serializable mirror of `crate::kill::signal::Signal` kept inside the
/// presentation layer so renderers never depend on kill internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SignalKind {
    Sigterm,
    Sigkill,
}

impl SignalKind {
    /// The short uppercase name shown to humans and in JSON (`"SIGTERM"`).
    pub const fn name(self) -> &'static str {
        match self {
            SignalKind::Sigterm => "SIGTERM",
            SignalKind::Sigkill => "SIGKILL",
        }
    }

    /// The polite visit if graceful, straight to the punch otherwise — the
    /// render-side equivalent of the `--force` decision.
    pub const fn from_force(force: bool) -> Self {
        if force {
            SignalKind::Sigkill
        } else {
            SignalKind::Sigterm
        }
    }
}

impl std::fmt::Display for SignalKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What happened to one process. Drives both the human STATUS column and the
/// machine `status` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatus {
    /// Informational row — no action was requested nor simulated.
    Info,
    /// Dry run: the row's `signal` is what *would* be sent.
    DryRun,
    /// A graceful `SIGTERM` freed the port.
    Terminated,
    /// `SIGKILL` freed the port.
    Killed,
    /// Signalling failed or the port refused to free.
    Failed,
}

/// The renderer's view of one process occupying a port: `ProcessInfo` plus the
/// per-row outcome. Every `ProcessInfo` field is mirrored so human and machine
/// renderers never reach back into the OS model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessResult {
    pub pid: u32,
    pub name: String,
    pub command: Option<String>,
    pub user: Option<String>,
    pub uptime_secs: Option<u64>,
    pub cwd: Option<String>,
    /// How this row ended up (defaults to [`ProcessStatus::Info`]).
    pub status: ProcessStatus,
    /// The signal that was / would be used, if any.
    pub signal: Option<SignalKind>,
    /// Failure detail for [`ProcessStatus::Failed`] rows.
    pub error: Option<String>,
}

impl From<&ProcessInfo> for ProcessResult {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid,
            name: process.name.clone(),
            command: process.command.clone(),
            user: process.user.clone(),
            uptime_secs: process.uptime_secs,
            cwd: process.cwd.clone(),
            status: ProcessStatus::Info,
            signal: None,
            error: None,
        }
    }
}

impl ProcessResult {
    /// Reconstruct the Phase-2 `ProcessInfo` this row was built from, for the
    /// OS-layer kill call (which still consumes the domain model).
    pub fn to_process_info(&self) -> ProcessInfo {
        ProcessInfo {
            pid: self.pid,
            name: self.name.clone(),
            command: self.command.clone(),
            user: self.user.clone(),
            uptime_secs: self.uptime_secs,
            cwd: self.cwd.clone(),
        }
    }
}

/// The renderer's view of one requested port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: Protocol,
    /// Whether the port is free. `None` when an inspection error (e.g. access
    /// denied) left us unable to tell.
    pub free: Option<bool>,
    /// Inspection-level error message, if the port could not be queried.
    pub error: Option<String>,
    /// One row per process occupying the port. Multiple entries mean the port
    /// is shared (e.g. `SO_REUSEPORT` worker threads).
    pub processes: Vec<ProcessResult>,
}

impl PortResult {
    /// A port that is definitively not bound.
    pub fn free(port: u16) -> Self {
        Self {
            port,
            protocol: Protocol::Tcp,
            free: Some(true),
            error: None,
            processes: Vec::new(),
        }
    }

    /// A bound port with one or more owning processes.
    pub fn occupied(port: u16, processes: Vec<ProcessInfo>) -> Self {
        Self {
            port,
            protocol: Protocol::Tcp,
            free: Some(false),
            error: None,
            processes: processes.iter().map(Into::into).collect(),
        }
    }

    /// A port that could not be inspected (permission denied, OS error).
    pub fn inspection_error(port: u16, protocol: Protocol, message: impl Into<String>) -> Self {
        Self {
            port,
            protocol,
            free: None,
            error: Some(message.into()),
            processes: Vec::new(),
        }
    }

    pub fn is_free(&self) -> bool {
        self.free == Some(true)
    }

    pub fn is_occupied(&self) -> bool {
        self.free == Some(false)
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// What the current invocation asked `pk` to do. Lets the human renderer pick
/// the correct STATUS column and per-port verdict lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunMode {
    /// Read-only inspection — `pk 3000`. No STATUS column.
    #[default]
    Inspect,
    /// `--dry-run`: the STATUS column shows what would happen, nothing is sent.
    DryRun,
    /// `--kill`/`--force` executed; rows carry their outcome in the STATUS column.
    Kill,
    /// The user declined the confirmation prompt.
    Aborted,
}

/// Tuning knobs for the human table renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableOptions {
    pub mode: RunMode,
}

impl TableOptions {
    pub fn new(mode: RunMode) -> Self {
        Self { mode }
    }

    /// Whether the STATUS column should be drawn at all. Per the product
    /// spec it only appears when an action was taken or simulated.
    pub fn show_status(&self) -> bool {
        matches!(self.mode, RunMode::DryRun | RunMode::Kill)
    }
}

impl Default for TableOptions {
    fn default() -> Self {
        Self {
            mode: RunMode::Inspect,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_result_mirrors_process_info() {
        let info = ProcessInfo {
            pid: 44122,
            name: "node".into(),
            command: Some("node server.js".into()),
            user: Some("alijoder".into()),
            uptime_secs: Some(3724),
            cwd: Some("/tmp".into()),
        };
        let row = ProcessResult::from(&info);
        assert_eq!(row.pid, info.pid);
        assert_eq!(row.name, info.name);
        assert_eq!(row.command, info.command);
        assert_eq!(row.user, info.user);
        assert_eq!(row.uptime_secs, info.uptime_secs);
        assert_eq!(row.cwd, info.cwd);
        assert_eq!(row.status, ProcessStatus::Info);
        assert_eq!(row.to_process_info(), info);
    }

    #[test]
    fn signal_kind_names_and_display() {
        assert_eq!(SignalKind::Sigterm.name(), "SIGTERM");
        assert_eq!(SignalKind::Sigkill.name(), "SIGKILL");
        assert_eq!(SignalKind::Sigterm.to_string(), "SIGTERM");
        assert_eq!(SignalKind::from_force(true), SignalKind::Sigkill);
        assert_eq!(SignalKind::from_force(false), SignalKind::Sigterm);
    }

    #[test]
    fn port_result_states() {
        assert!(PortResult::free(3000).is_free());
        let occ = PortResult::occupied(3000, vec![ProcessInfo::bare(12, "x".into())]);
        assert!(occ.is_occupied() && !occ.is_free());
        let err = PortResult::inspection_error(80, Protocol::Tcp, "denied");
        assert!(err.is_error() && !err.is_free() && !err.is_occupied());
    }

    #[test]
    fn status_serializes_snake_case_and_signals_uppercase() {
        assert_eq!(
            serde_json::to_string(&ProcessStatus::DryRun).unwrap(),
            r#""dry_run""#
        );
        assert_eq!(
            serde_json::to_string(&SignalKind::Sigterm).unwrap(),
            r#""SIGTERM""#
        );
    }

    #[test]
    fn show_status_only_after_action_or_dry_run() {
        assert!(!TableOptions::default().show_status());
        assert!(TableOptions::new(RunMode::DryRun).show_status());
        assert!(TableOptions::new(RunMode::Kill).show_status());
        assert!(!TableOptions::new(RunMode::Aborted).show_status());
    }
}
