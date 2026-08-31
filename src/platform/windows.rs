//! Windows port → process discovery (via `netstat`).
//!
//! ## Approach: shell out to `netstat`
//!
//! Windows ships `netstat` whose `-ano` flags emit the owning PID:
//!
//! ```text
//! netstat -ano -p TCP
//! ```
//!
//! The final column is the PID. The `Foreign Address` column shows
//! `0.0.0.0:0`/`[::]:0` or `127.0.0.1:0` when a listener, but matching by PID
//! alone is unreliable (ephemeral ports), so we filter against the local port
//! *and* `LISTENING` state.
//!
//! ## IO / parsing separation
//!
//! * **IO** (`run_netstat`) invokes the binary.
//! * **Parsing** (`parse_netstat`) consumes raw text into rows, unit-tested.
//!
//! ## Name resolution is deferred to `sysinfo`
//!
//! We do **not** call `CreateToolhelp32Snapshot` per PID here — that takes a
//! whole-process snapshot for every process, which is unacceptably slow on
//! Windows. Each row is yielded as a placeholder `"pid-{pid}"` name; the shared
//! [`crate::process::enrich::ProcessEnricher`] (one optimized `sysinfo`
//! snapshot per batch) overwrites it with the real executable name.

use std::process::Command;

use crate::error::AppError;
use crate::process::ProcessInfo;

const NETSTAT: &str = "netstat";

/// One parsed `netstat -ano` row that is in `LISTENING` state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetstatRow {
    pub pid: u32,
    pub local_port: u16,
}

/// Parse raw `netstat -ano` output, keeping only `LISTENING` rows for the
/// given port. Tolerates the header, blank lines, and malformed rows.
///
/// Row shape (`-p TCP` on modern Windows):
/// `TCP 0.0.0.0:3000 0.0.0.0:0 LISTENING 44122`
pub fn parse_netstat(output: &str, port: u16) -> Vec<NetstatRow> {
    let mut rows = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Expect: TCP <local> <foreign> <state> <pid>
        if fields.len() != 5 {
            continue;
        }
        let state_ok = fields[3].eq_ignore_ascii_case("LISTENING");
        let Some(local_port) = port_of(fields[1]) else {
            continue;
        };
        let Some(pid) = fields[4].parse::<u32>().ok() else {
            continue;
        };
        if state_ok && local_port == port {
            rows.push(NetstatRow { pid, local_port });
        }
    }
    rows
}

/// Extract the port from a `host:port` (or `[host]:port`) local address.
fn port_of(local_address: &str) -> Option<u16> {
    if local_address.starts_with('[') {
        // [::1]:3000
        let rest = local_address.rsplit(']').next()?.strip_prefix(':')?;
        rest.parse().ok()
    } else if let Some(idx) = local_address.rfind(':') {
        local_address[idx + 1..].parse().ok()
    } else {
        None
    }
}

/// Run `netstat -ano -p TCP` and return raw stdout, or an actionable error.
fn run_netstat() -> Result<String, AppError> {
    let output = Command::new(NETSTAT)
        .args(["-ano", "-p", "TCP"])
        .output()
        .map_err(|e| AppError::OsCommandFailed {
            command: NETSTAT,
            message: format!("could not spawn `{NETSTAT}`: {e}"),
        })?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(AppError::OsCommandFailed {
            command: NETSTAT,
            message: stderr.trim().to_string(),
        })
    }
}

/// Return the processes bound to `port` (TCP, LISTENING). Empty vec when free.
///
/// A single process binding the same port over both IPv4 and IPv6 produces two
/// `netstat` rows for the same PID; those are collapsed to one [`ProcessInfo`]
/// per PID so the CLI never shows the same process twice.
pub fn get_processes_on_port(port: u16) -> Result<Vec<ProcessInfo>, AppError> {
    let raw = run_netstat()?;
    let rows = parse_netstat(&raw, port);
    let procs: Vec<ProcessInfo> = rows
        .into_iter()
        .map(|r| ProcessInfo::bare(r.pid, format!("pid-{}", r.pid)))
        .collect();
    Ok(dedup_by_pid(procs))
}

/// Collapse a list into one [`ProcessInfo`] per PID, preserving first-seen order.
///
/// `netstat` emits one row per (process, address family). When a process listens
/// on both IPv4 and IPv6 for the same port it appears twice; keeping one entry
/// per PID prevents duplicate CLI rows.
fn dedup_by_pid(procs: Vec<ProcessInfo>) -> Vec<ProcessInfo> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(procs.len());
    for p in procs {
        if seen.insert(p.pid) {
            out.push(p);
        }
    }
    out
}

/// Report whether nothing is bound to `port` (TCP, LISTENING).
pub fn is_port_free(port: u16) -> Result<bool, AppError> {
    let raw = run_netstat()?;
    Ok(parse_netstat(&raw, port).is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_NETSTAT: &str = r#"Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       44122
  TCP    [::]:3000              [::]:0                 LISTENING       51204
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       99999
  TCP    127.0.0.1:3000         127.0.0.1:54321         ESTABLISHED     77777
  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       12345
"#;

    #[test]
    fn keeps_only_listening_rows_for_target_port() {
        let rows = parse_netstat(MOCK_NETSTAT, 3000);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].pid, 44122);
        assert_eq!(rows[2].pid, 12345);
    }

    #[test]
    fn ignores_established_and_other_ports() {
        let rows = parse_netstat(MOCK_NETSTAT, 3000);
        assert!(!rows.iter().any(|r| r.pid == 77777)); // ESTABLISHED
        assert!(!rows.iter().any(|r| r.pid == 99999)); // port 8080
    }

    #[test]
    fn parses_ipv6_bracketed_addresses() {
        assert_eq!(port_of("[::]:3000"), Some(3000));
        assert_eq!(port_of("0.0.0.0:8080"), Some(8080));
        assert_eq!(port_of("127.0.0.1:3000"), Some(3000));
        assert_eq!(port_of("garbage"), None);
    }

    #[test]
    fn empty_and_header_only_output_yields_nothing() {
        assert!(parse_netstat("", 3000).is_empty());
        assert!(parse_netstat("Proto  Local Address  Foreign  State  PID\n", 3000).is_empty());
    }

    // Regression: one process binding the same port on both IPv4 and IPv6 yields
    // two netstat rows for the same PID, which must collapse to a single entry.
    #[test]
    fn ipv4_and_ipv6_listeners_for_same_pid_deduplicate() {
        let dual = r#"Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:3000           0.0.0.0:0              LISTENING       44122
  TCP    [::]:3000              [::]:0                 LISTENING       44122
"#;
        let rows = parse_netstat(dual, 3000);
        assert_eq!(rows.len(), 2, "both address families must be parsed");
        assert_eq!(rows[0].pid, rows[1].pid);

        let procs: Vec<ProcessInfo> = rows
            .into_iter()
            .map(|r| ProcessInfo::bare(r.pid, format!("pid-{}", r.pid)))
            .collect();
        let deduped = dedup_by_pid(procs);
        assert_eq!(deduped.len(), 1, "same PID across IPv4/IPv6 must collapse");
        assert_eq!(deduped[0].pid, 44122);
    }
}
