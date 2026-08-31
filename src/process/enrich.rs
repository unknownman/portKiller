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
//! # Performance: one scoped `sysinfo::System` per batch
//!
//! Building a [`sysinfo::System`] and refreshing the process table is expensive.
//! Constructing it *per process* — as inspection of a port range with many
//! processes would do — causes redundant heavy system scanning. The [`System`]
//! here is created once per inspection batch (lazily), and [`ProcessEnricher::enrich_all`]
//! refreshes **only the exact PIDs we discovered**, so a handful of targets never
//! scans the whole process table. The single user list is shared across the batch.

use crate::process::ProcessInfo;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

/// Reusable, batch-aware enricher backed by one shared [`sysinfo::System`].
///
/// Create one `ProcessEnricher` per inspection and call [`ProcessEnricher::enrich_all`]
/// for every discovered process. The system snapshot is populated lazily, on the
/// first call, and only for the PIDs actually requested.
pub struct ProcessEnricher {
    system: System,
    users: Users,
}

impl ProcessEnricher {
    /// Build an enricher with an empty (unrefreshed) system and user list.
    ///
    /// No OS scanning happens here; the process table is refreshed — scoped to
    /// the exact PIDs — by [`ProcessEnricher::enrich_all`].
    pub fn new() -> Self {
        Self {
            system: System::new(),
            users: Users::new_with_refreshed_list(),
        }
    }

    /// The process metadata to collect. Avoids CPU/memory work that is
    /// irrelevant to port inspection.
    fn refresh_kind() -> ProcessRefreshKind {
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet)
            .with_cwd(UpdateKind::OnlyIfNotSet)
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_environ(UpdateKind::OnlyIfNotSet)
    }

    /// Enrich a single process against the shared system snapshot, leaving any
    /// metadata the platform already provided untouched (except the placeholder
    /// name, which is replaced as described below).
    ///
    /// Some platforms can only supply a PID cheaply and yield a synthetic
    /// `"pid-{n}"` name (e.g. Windows). `sysinfo` reads the real executable
    /// name from the same snapshot it already took for command/user/cwd, so we
    /// use it to overwrite that placeholder (or an empty name) at no extra cost.
    ///
    /// Callers must have populated the snapshot first (via [`ProcessEnricher::enrich_all`]);
    /// a PID that is not in the snapshot is left untouched.
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

        if process.name.starts_with("pid-") || process.name.is_empty() {
            let real_name = sysinfo_proc.name().to_string_lossy().into_owned();
            if !real_name.is_empty() {
                process.name = real_name;
            }
        }

        if process.command.is_none() {
            let args: Vec<String> = sysinfo_proc
                .cmd()
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            let cmd = args.join(" ").trim().to_string();
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
    ///
    /// Before looping, it refreshes the system snapshot **only** for the PIDs in
    /// the batch — the OS fetches metadata for exactly the processes we care
    /// about, never the entire table.
    pub fn enrich_all(&mut self, processes: Vec<ProcessInfo>) -> Vec<ProcessInfo> {
        let pids: Vec<Pid> = processes.iter().map(|p| Pid::from_u32(p.pid)).collect();
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&pids),
            true,
            Self::refresh_kind(),
        );
        processes.into_iter().map(|p| self.enrich(p)).collect()
    }
}

impl Default for ProcessEnricher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_placeholder_name_is_overwritten_by_sysinfo() {
        // The test's own process is guaranteed to exist in the snapshot, so its
        // PID resolves. A synthetic "pid-{pid}" placeholder must be replaced by
        // the real executable name from sysinfo.
        let pid = std::process::id();
        let mut enricher = ProcessEnricher::new();
        let enriched = enricher.enrich_all(vec![ProcessInfo::bare(pid, format!("pid-{pid}"))]);

        let name = &enriched[0].name;
        assert!(
            !name.is_empty(),
            "placeholder name must be replaced with the real process name"
        );
        assert!(
            !name.starts_with("pid-"),
            "name must no longer be a synthetic pid- placeholder"
        );
    }
}
