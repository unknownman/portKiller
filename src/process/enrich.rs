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

use crate::process::ProcessInfo;
use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind, Users};

/// Populate `command`, `user`, and `uptime_secs` on `process` from `sysinfo`,
/// leaving any metadata the platform already provided untouched.
///
/// Returns the (possibly unchanged) process. This is deliberately not `Result`:
/// a best-effort enrichment failure should not abort an inspection.
pub fn enrich_process(mut process: ProcessInfo) -> ProcessInfo {
    let pid = Pid::from_u32(process.pid);

    // Query only the process metadata we actually need, avoiding CPU/memory
    // work that is irrelevant here.
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessRefreshKind::new()
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet)
            .with_cwd(UpdateKind::OnlyIfNotSet)
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_environ(UpdateKind::OnlyIfNotSet),
    );

    let Some(sysinfo_proc) = system.process(pid) else {
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
        process.user = sysinfo_proc.user_id().and_then(|uid| {
            Users::new_with_refreshed_list()
                .get_user_by_id(uid)
                .map(|u| u.name().to_string())
        });
    }

    if process.uptime_secs.is_none() {
        process.uptime_secs = Some(sysinfo_proc.run_time());
    }

    process
}
