//! Enrich a bare `ProcessInfo` (pid + name) with rich metadata using `sysinfo`.
//!
//! The platform discovery layers only guarantee a PID (and cannot read
//! command/user/uptime for every process on every OS). This module fills those
//! gaps from `sysinfo` across all platforms, honoring the promise the README
//! and CLI make: command, user, and uptime where the OS can provide them.
//!
//! The enrichment is **best-effort and additive**: it never overwrites
//! metadata the platform already supplied, and it never fails the caller — if
//! `sysinfo` cannot resolve a field, the process keeps whatever it had.
//!
//! # Performance: one `sysinfo::System` per batch
//!
//! Building a [`sysinfo::System`] and refreshing the process table is expensive.
//! Constructing it *per process* — as inspection of a port range with many
//! processes would do — causes redundant heavy system scanning. Instead we
//! create a single [`ProcessEnricher`] per inspection batch and reuse its
//! `system` (and its user list) for every discovered process.

use crate::process::ProcessInfo;
use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind, Users};

/// Reusable, batch-aware enricher backed by one shared [`sysinfo::System`].
///
/// Create one `ProcessEnricher` per inspection and call [`ProcessEnricher::enrich`]
/// (or [`ProcessEnricher::enrich_all`]) for every discovered process. The system
/// snapshot and user list are refreshed exactly once, in [`ProcessEnricher::new`],
/// eliminating the per-process instantiation overhead.
pub struct ProcessEnricher {
    system: System,
    users: Users,
}

impl ProcessEnricher {
    /// Build an enricher, refreshing the process table (with only the metadata
    /// we need) and the user list exactly once.
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_processes_specifics(Self::refresh_kind());
        let users = Users::new_with_refreshed_list();
        Self { system, users }
    }

    /// The process metadata to collect. Avoids CPU/memory work that is
    /// irrelevant to port inspection.
    fn refresh_kind() -> ProcessRefreshKind {
        ProcessRefreshKind::new()
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet)
            .with_cwd(UpdateKind::OnlyIfNotSet)
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_environ(UpdateKind::OnlyIfNotSet)
    }

    /// Enrich a single process against the shared system snapshot, leaving any
    /// metadata the platform already provided untouched.
    ///
    /// Returns the (possibly unchanged) process. This is deliberately not
    /// `Result`: a best-effort enrichment failure should not abort an inspection.
    pub fn enrich(&mut self, mut process: ProcessInfo) -> ProcessInfo {
        let pid = Pid::from_u32(process.pid);
        let Some(sysinfo_proc) = self.system.process(pid) else {
            // The process vanished between discovery and enrichment; keep the
            // bare metadata rather than guessing.
            return process;
        };

        if process.command.is_none() {
            let cmd = sysinfo_proc.cmd().join(" ").trim().to_string();
            if !cmd.is_empty() {
                process.command = Some(cmd);
            }
        }

        if process.user.is_none() {
            process.user = sysinfo_proc
                .user_id()
                .and_then(|uid| self.users.get_user_by_id(uid).map(|u| u.name().to_string()));
        }

        if process.uptime_secs.is_none() {
            process.uptime_secs = Some(sysinfo_proc.run_time());
        }

        process
    }

    /// Enrich a whole batch of processes against the shared snapshot.
    pub fn enrich_all(&mut self, processes: Vec<ProcessInfo>) -> Vec<ProcessInfo> {
        processes.into_iter().map(|p| self.enrich(p)).collect()
    }
}

impl Default for ProcessEnricher {
    fn default() -> Self {
        Self::new()
    }
}
